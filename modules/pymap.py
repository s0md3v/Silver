import re
import subprocess

from core.utils import load_json

def pymap(ip, ports, exclude):
	if ip not in exclude:
		result = {}
		result[ip] = {}
		ports = ','.join([str(port) for port in ports])
		info = subprocess.getoutput('nmap -oX - -sV %s -p%s' % (ip, ports))
		matches = re.finditer(r'<port protocol="\w+" portid="(\d+)"><state state="([^"]+)" reason="[^"]+" reason_ttl="\d+"/><service name="([^"]*)"( product="([^"]*)")?( version="([^"]*)")?.*?>.*?(<cpe>([^<]*))?', info)
		if matches:
			for match in matches:
				port = match.group(1)
				result[ip][port] = {}
				result[ip][port]['state'] = match.group(2)
				result[ip][port]['service'] = match.group(3)
				result[ip][port]['software'] = match.group(5)
				result[ip][port]['version'] = match.group(7)
				result[ip][port]['cpe'] = match.group(9)
				if not match.group(7) and match.group(9):
					if match.group(9).count(':') > 3:
						result[ip][port]['version'] = match.group(9).split(':')[-1]
		return result
	else:
		return 'cached'
