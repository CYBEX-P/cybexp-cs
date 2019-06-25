# proc\parsescriipts\parse_cowrie.py


import json, pdb
from datetime import datetime as dt
from tahoe import Attribute, Object, Event

def parse_unr_honeypot(line, orgid, tzname = 'UTC'):
    data = json.loads(line)

    try:
        timestamp = data["@timestamp"]
    except:
        return None
    timestamp = timestamp.replace("Z", "+00:00")
    timestamp = dt.fromisoformat(timestamp)
    timestamp = timestamp.timestamp()

    url = data['url']
    filename = url.split('/')[-1]
    sha256 = data['shasum']
    
    url = Attribute('url', data['url'])
    url = Object('url', [url])

    filename = Attribute('filename', filename)
    sha256 = Attribute('sha256', sha256)
    file = Object('file', [filename, sha256])

    file_download_event = Event('file_download', [url, file], timestamp)

    from pprint import pprint
    pprint(vars(url))
    print('\n')
    pprint(vars(file))
    print('\n')
    pprint(vars(file_download_event))
    pdb.set_trace()
        
    return None

