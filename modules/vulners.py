import time

from core.requester import requester
from core.utils import write_json, load_json

file = './db/vulners_cache.json'

database = load_json(file)
current_time = int(time.time())
if 'time' not in database or (current_time - database.get('time', 0)) > 86400:
    database = {'by_cpe':{}, 'by_version':{}}
database['time'] = current_time

def vulners(software, version, cpe=False):
    if software and version:
        pass
    else:
        return False
    cached = query_cache(software, version, cpe)
    if cached:
        if cached == 'vulnerable':
            return True
        else:
            return False
    kind = 'software'
    if cpe:
        kind = 'cpe'
    data = '{"software": "%s", "version": "%s", "type" : "%s", "maxVulnerabilities" : %i}' % (software, version, kind, 1)
    response = requester('https://vulners.com/api/v3/burp/software/', get=False, data=data).text
    cache(software, version, response, cpe)
    if 'Nothing found for Burpsuite search request' in response:
        return False
    return True

def query_cache(software, version, cpe):
    if cpe:
        if software in database['by_cpe']:
            if database['by_cpe'][software] == True:
                return 'vulnerable'
            else:
                return 'not-vulerable'
            return False
    else:
        if software in database['by_version']:
            if version in database['by_version'][software]:
                if database['by_version'][software][version] == True:
                    return 'vulnerable'
                else:
                    return 'not-vulerable'
            return False
    return False

def cache(software, version, response, cpe):
    vulnerable = True
    if 'Nothing found for Burpsuite search request' in response:
        vulnerable = False
    if cpe:
        if software not in database['by_cpe']:
            database['by_cpe'][software] = vulnerable
    else:
        if software not in database['by_version']:
            database['by_version'][software] = {}
        if version not in database['by_version'][software]:
            database['by_version'][software][version] = vulnerable
    write_json(file, database)
