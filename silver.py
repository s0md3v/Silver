#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import psutil
import argparse
from multiprocessing import Pool

import core.memory
from modules.pymap import pymap
from modules.shodan import shodan
from modules.vulners import vulners
from core.colors import run, bad, end, good, info, white
from core.utils import notify, load_json, write_json, parse_masscan

print('''
\t%s𝘴𝘪𝘭𝘷𝘦𝘳%s
''' % (white, end))

cwd = sys.path[0]

parser = argparse.ArgumentParser()
parser.add_argument(help='host(s) to scan', dest='host', nargs='?')
parser.add_argument('-i', help='path of input file', dest='input_file')
parser.add_argument('-m', '--method', help='software or cpe', dest='method')
parser.add_argument('-r', '--rate', help='masscan packets per second rate', dest='rate', type=int, default=1000)
parser.add_argument('-t', '--threads', help='nmap threads to run in parallel', dest='threads', type=int)
parser.add_argument('-q', '--quick', help='only scan top ~1000 ports', dest='quick', action='store_true')
args = parser.parse_args()

host = args.host
quick = args.quick
method = args.method
threads = args.threads
input_file = args.input_file or ('%s/targets.txt' % cwd)
savefile = cwd + '/result-' + input_file.split('/')[-1]

if not host:
	quit('%s No hosts to scan.' % bad)

arg_dict = vars(args)
for key in arg_dict:
	core.memory.global_vars[key] = arg_dict[key]
core.memory.global_vars['shodan_queries'] = 0

hostfile = ''
if not host:
	host = ' '
	hostfile = '-iL ' + input_file
else:
	host = ' %s ' % host

use_cpe = True
if method == 'software':
	use_cpe = False

ports_to_scan = '0-65535'
if quick:
	ports_to_scan = ','.join(core.memory.config['top_ports'])

database = {}

print('%s Deploying masscan' % run)
masscan_saved = load_json(savefile)

if not masscan_saved:
	file = open(savefile, 'w+')
	file.close()

exclude = [host for host in masscan_saved]
if exclude:
	exclude = ' --exclude ' + ','.join(exclude) + ' '
else:
	exclude = ''

os.system('masscan%s-p%s --rate %i -oG %s %s %s >/dev/null 2>&1' % (host, ports_to_scan, args.rate, savefile, hostfile, exclude))
master_db = parse_masscan(savefile)
for host in masscan_saved:
	master_db[host] = masscan_saved[host]
write_json(savefile, master_db)
print('%s Result saved to %s' % (info, savefile))

exclude = []
cached_hosts = load_json(savefile)
for host in cached_hosts:
	for port in cached_hosts[host]:
		if 'software' in cached_hosts[host][port]:
			exclude.append(host)
		break

count = 0
shodan_count = core.memory.config['max_shodan_credits'] * 20
shodan_eligible = []
for host in master_db:
	if host not in exclude:
		if len(master_db[host]) >= core.memory.config['shodan_call_threshold'] and core.memory.config['shodan_api_key']:
			shodan_eligible.append(host)
			shodan_count -= 1
		for port in master_db[host]:
			count += 1

print('%s %i services to fingerprint' % (run, count))

if shodan_eligible:
	for host in shodan_eligible:
		result = shodan(host)
		for port in result:
			master_db[port] = result[port]
		write_json(savefile, master_db)
	exclude = []
	for host in master_db:
		for port in master_db[host]:
			if 'software' in master_db[host][port]:
				exclude.append(host)
			break
print('%s ETA: %i seconds ' % (info, count * 22))

num_cpus = threads or psutil.cpu_count()
if num_cpus > len(master_db):
	num_cpus = len(master_db)

if num_cpus > 1:
	print('%s Spawning %i nmap instances in parallel' % (run, num_cpus))
else:
	print('%s Spawning 1 nmap instance' % run)

if num_cpus != 0:
	pool = Pool(processes=num_cpus)

	results = [pool.apply_async(pymap, args=(host, master_db[host], exclude)) for host in master_db]

	for p in results:
		result = p.get()
		if result == 'cached':
			continue
		for host in result:
			master_db[host] = result[host]
			write_json(savefile, master_db)

print('%s Updated %s' % (info, savefile))

print('%s Looking for vulnerablilites' % run)

for ip in master_db:
	for port in master_db[ip]:
		cpe = master_db[ip][port]['cpe']
		name = master_db[ip][port]['software']
		version = master_db[ip][port]['version']
		software = name
		if use_cpe:
			software = cpe
		is_vuln = vulners(software, version, cpe=use_cpe)
		if is_vuln:
			message = '%s %s running on %s:%s is outdated' % (name, version, ip, port)
			notify('[Vuln] %s' % message)
			print('%s %s' % (good, message))

print('%s Scan completed' % good)
