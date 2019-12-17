import re
import json
import requests

from core.memory import config

def reader(path):
	try:
	    with open(path, 'r') as f:
	        result = [line.rstrip('\n').encode('utf-8').decode('utf-8') for line in f]
	    return '\n'.join(result)
	except:
		return False

def load_json(path):
	try:
		return json.loads(reader(path))
	except:
		return {}

def write_json(path, data):
    with open(path, 'w+') as file:
        json.dump(data, file, indent=4)

def parse_masscan(file):
	data = {}
	result = reader(file)
	matches = re.finditer(r'Host: (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).+?Ports: (\d+)', result)
	for match in matches:
		ip = match.group(1)
		port = match.group(2)
		if ip not in data:
			data[ip] = {}
		data[ip][port] = {}
	return data

def notify(message, service='slack'):
	if service == 'slack':
		webhook_url = config['slack_webook']
		if webhook_url:
			data = {'text': message}
			requests.post(webhook_url, json=data)
