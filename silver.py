#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import psutil
import argparse
from multiprocessing import Pool

import core.memory
from modules.pymap import pymap, parse_result
from modules.shodan import shodan
from modules.vulners import vulners
from core.resolver import resolver
from core.colors import run, bad, end, good, info, white
from core.utils import notify, load_json, write_json, parse_masscan

print('''
\t%s𝘴𝘪𝘭𝘷𝘦𝘳%s
''' % (white, end))

if os.geteuid() != 0:
	quit('%s You need to run Silver a root!' % info)

cwd = sys.path[0]

parser = argparse.ArgumentParser()
parser.add_argument(help='host(s) to scan', dest='host', nargs='?')
parser.add_argument('-i', help='path of input file', dest='input_file')
parser.add_argument('-p', help='ports to scan', dest='ports')
parser.add_argument('-m', help='software or cpe', dest='method')
parser.add_argument('-o', help='output file name', dest='outname')
parser.add_argument('-r', '--rate', help='masscan packets per second rate', dest='rate', type=int, default=10000)
parser.add_argument('-t', '--threads', help='nmap threads to run in parallel', dest='threads', type=int)
parser.add_argument('-q', '--quick', help='only scan top ~1000 ports', dest='quick', action='store_true')
parser.add_argument('--shodan', help='use shodan api for scanning', dest='use_shodan', action='store_true')
args = parser.parse_args()

targets = resolver(args.host.split(',')) if args.host else []
quick = args.quick
method = args.method
threads = args.threads
input_file = args.input_file

target_name = ''
if targets:
	target_name = targets[0].split('/')[0]
elif input_file:
	target_name = input_file.split('/')[-1]
else:
	quit('%s No hosts to scan.' % bad)

if args.outname:
	target_name = args.outname.split('/')[-1].split('.')[0]

savefile = args.outname if args.outname else cwd + '/result-' + target_name + '.json'
nmapfile = cwd + '/nmap-' + target_name + '.xml'

if input_file:
	print('%s Resolving hostnames to IPs for masscan' % run)
	targets = resolver(input_file)

cached_db = load_json(savefile)
if args.use_shodan:
	result = shodan(targets, cached_db)
	write_json(savefile, result)
	print('%s Output saved to %s' % (info, savefile))
	quit()

arg_dict = vars(args)
for key in arg_dict:
	core.memory.global_vars[key] = arg_dict[key]

flat_targets = ','.join(targets)
hostfile = '-iL ' + input_file if args.input_file else ''
host = ' %s ' % flat_targets if not args.input_file else ' '

use_cpe = True if method == 'software' else False

ports_to_scan = '0-65535'
if quick:
	ports_to_scan = ','.join(core.memory.config['top_ports'])
elif args.ports:
	ports_to_scan = args.ports

print('%s Deploying masscan' % run)

if not cached_db:
	file = open(savefile, 'w+')
	file.close()

exclude = [host for host in cached_db]
if exclude:
	exclude = ' --exclude ' + ','.join(exclude) + ' '
else:
	exclude = ''

os.system('masscan %s -p%s --rate %i -oG %s %s >/dev/null 2>&1' % (flat_targets, ports_to_scan, args.rate, savefile, exclude))
master_db = parse_masscan(savefile)
for host in cached_db:
	master_db[host] = cached_db[host]
write_json(savefile, master_db)
print('%s Result saved to %s' % (info, savefile))

exclude = []
cached_hosts = load_json(savefile)
for host, data in cached_hosts.items():
	if data.get('ports', False):
		exclude.append(host)

count = 0
for host in master_db:
	for port in master_db[host]:
		count += 1

print('%s %i services to fingerprint' % (run, count))

num_cpus = threads or psutil.cpu_count()
if num_cpus > len(master_db):
	num_cpus = len(master_db)

if num_cpus > 1:
	print('%s Spawning %i nmap instances in parallel' % (run, num_cpus))
else:
	print('%s Spawning 1 nmap instance' % run)

if num_cpus != 0:
	print('%s ETA: %i seconds ' % (info, count * 22/num_cpus))
	pool = Pool(processes=num_cpus)

	results = [pool.apply_async(pymap, args=(host, master_db[host], exclude, nmapfile)) for host in master_db]

	for p in results:
		result = p.get()
		if result == 'cached':
			continue
	result = parse_result(nmapfile)
	for host in result:
		master_db[host] = result[host]
		master_db[host]['source'] = 'nmap'

write_json(savefile, master_db)

print('%s Updated %s' % (info, savefile))

print('%s Looking for vulnerablilites' % run)

for ip in master_db:
	for port in master_db[ip]['ports']:
		cpe = master_db[ip]['ports'][port]['cpe']
		name = master_db[ip]['ports'][port]['software']
		version = master_db[ip]['ports'][port]['version']
		software = name
		if use_cpe:
			software = cpe
		is_vuln = vulners(software, version, cpe=use_cpe)
		if is_vuln:
			message = '%s %s running on %s:%s is outdated' % (name, version, ip, port)
			master_db[ip]['ports'][port]['vuln'] = True
			notify('[Vuln] %s' % message)
			print('%s %s' % (good, message))
		else:
			master_db[ip]['ports'][port]['vuln'] = False

write_json(savefile, master_db)
print('%s Scan completed' % good)
