import re
import sys
import socket

import concurrent.futures

def resolve(hostname):
	try:
		return socket.gethostbyaddr(hostname)[2][0]
	except socket.gaierror:
		return ''

def handler(hostnames):
	ips = set()
	threadpool = concurrent.futures.ThreadPoolExecutor(max_workers=10)
	futures = (threadpool.submit(resolve, hostname) for hostname in hostnames)
	for i, result in enumerate(concurrent.futures.as_completed(futures)):
		if result.result():
			ips.add(result.result())
	return list(ips)

def resolver(hostnames):
	if type(hostnames) == str:
		resolved = []
		all_ips = set()
		with open(hostnames, 'r') as inpfile:
			for line in inpfile:
				line = line.strip()
				if re.search(r'\d+\.\d+\.\d+\.\d+', line):
					result.add(line)
				else:
					resolved.append(line)
		result = handler(filter(None, resolved))
		all_ips.update(set(result))
		with open('silver-' + hostnames, 'w+') as outfile:
			for ip in all_ips:
				outfile.write(ip + '\n')
		return 'silver-' + hostnames
	else:
		return handler(hostnames)
