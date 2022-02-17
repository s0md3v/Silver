from core.colors import good
from core.utils import notify
from core.requester import requester

def shodan(ips, exclude):
	result = {}
	for ip in ips:
		if ip in exclude:
			if exclude[ip].get('vuln', False):
				message = '%s has a vulnerable service' % (ip)
				notify('[Vuln] %s' % message)
				print('%s %s' % (good, message))
				continue
		result[ip] = {}
		result[ip]['source'] = 'shodan'
		data = requester('https://internetdb.shodan.io/%s' % ip).json()
		if '"No information available"' in data:
			continue
		elif data['vulns']:
			result[ip]['vuln'] = True
			message = '%s has a vulnerable service' % (ip)
			notify('[Vuln] %s' % message)
			print('%s %s' % (good, message))
		result[ip]['ports'] = {}
		for port in data['ports']:
			result[ip]['ports'][port] = {'state': 'open'}
	return result
