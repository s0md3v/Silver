import warnings
import requests

warnings.filterwarnings('ignore') # Disable SSL related warnings

def requester(url, get=True, data={}):
    if get:
        response = requests.get(url, params=data, verify=False)
    else:
        response = requests.post(url, data=data, verify=False)
    return response
