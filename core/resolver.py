import re
import socket

import concurrent.futures

def resolve(hostname):
	if re.search(r'^\d+\.\d+\.\d+\.\d+', hostname):
		return hostname
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
		with open(hostnames, 'r') as inpfile:
			for line in inpfile:
				resolved.append(line)
		result = set(handler(filter(None, resolved)))
		with open('silver-' + hostnames, 'w+') as outfile:
			for ip in result:
				outfile.write(ip + '\n')
		return 'silver-' + hostnames
	else:
		return handler(hostnames)
