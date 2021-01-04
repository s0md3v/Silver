import core.memory
from core.colors import good
from core.utils import notify
from core.requester import requester
from modules.vulners import vulners, cache

def shodan(ip):
	result = {ip : {}}
	response = requester('https://api.shodan.io/shodan/host/%s?key=%s' % (ip, core.memory.config['shodan_api_key']))
	data = response.json()['data']
	core.memory.global_vars['shodan_queries'] += 1
	if data:
		for each in data:
			port = each['port']
			result[ip][port] = {}
			software, version = None, None
			if 'product' in each:
				software = each['product']
				result[ip][port]['software'] = software
			else:
				result[ip][port]['software'] = ''
			if 'cpe' in each:
				cpes = each['cpe']
				for cpe in cpes:
					if software in cpe:
						result[ip][port]['cpe'] = cpe
						break
				else:
					result[ip][port]['cpe'] = cpes[0]
			else:
				result[ip][port]['cpe'] = ''
			cpe_boolean = False
			if result[ip][port]['cpe']:
				cpe_boolean = True
			if 'version' in each:
				version = each['version']
				if cpe_boolean and cpe.count(':') > 3:
					version = cpe.split(':')[-1]
				result[ip][port]['version'] = version
			elif cpe_boolean and cpe.count(':') > 3:
				result[ip][port]['version'] = cpe.split(':')[-1]
			else:
				result[ip][port]['version'] = ''
			if 'vulns' in each:
				cache(software, version, 'dummy', '')
			elif software and version:
				if cpe_boolean:
					for cpe in cpes:
						software = cpe
						if cpe.count(':') > 3:
							version = cpe.split(':')[-1]
						is_vuln = vulners(software, version, cpe=cpe_boolean)
						if is_vuln:
							message = '%s %s running on %s:%s is outdated' % (each['product'], version, ip, each['port'])
							notify('[Vuln] %s' % message)
							print('%s %s' % (good, message))
				else:
					is_vuln = vulners(software, version, cpe=cpe_boolean)
					if is_vuln:
						message = '%s %s running on %s:%s is outdated' % (each['product'], version, ip, each['port'])
						notify('[Vuln] %s' % message)
						print('%s %s' % (good, message))
	return result
