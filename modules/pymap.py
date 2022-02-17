import re
import subprocess

def parse_result(nmapfile):
	result = {}
	with open(nmapfile, 'r') as file:
		lines = '\n'.join(file.readlines())
		hosts = lines.split('</host>')
		for host in hosts[:-1]:
			ip = re.search('<address addr="([^"]+)"', host).group(1)
			result[ip] = {}
			result[ip]['ports'] = {}
			result[ip]['vuln'] = False
			matches = re.finditer(r'<port protocol="\w+" portid="(\d+)"><state state="([^"]+)" reason="[^"]+" reason_ttl="\d+"/><service name="([^"]*)"( product="([^"]*)")?( version="([^"]*)")?.*?>.*?(<cpe>([^<]*))?', host)
			for match in matches:
				port = match.group(1)
				result[ip]['ports'][port] = {}
				result[ip]['ports'][port]['state'] = match.group(2)
				result[ip]['ports'][port]['service'] = match.group(3)
				result[ip]['ports'][port]['software'] = match.group(5)
				result[ip]['ports'][port]['version'] = match.group(7)
				result[ip]['ports'][port]['cpe'] = match.group(9)
				if not match.group(7) and match.group(9):
					if match.group(9).count(':') > 3:
						result[ip]['ports'][port]['version'] = match.group(9).split(':')[-1]
	return result

def pymap(ip, ports, exclude, nmapfile):
	if ip not in exclude:
		ports = ','.join([str(port) for port in ports])
		subprocess.getoutput('nmap -Pn -oX %s -sV %s -p%s --append-output' % (nmapfile, ip, ports))
		return 'success'
	else:
		return 'cached'
