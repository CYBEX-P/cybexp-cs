import pdb
from datetime import datetime as dt
from tahoe import Attribute, Object, Event, Session

_PROJECTION = {"_id":0, "filters":0, "bad_data":0}

def filt_cowrie(backend):
    filt_id = "filter--ad8c8d0c-0b25-4100-855e-06350a59750c"
    query = [{"raw_type" : "x-unr-honeypot"}, {"filters" : { "$ne": filt_id }}, { "data.eventid" : {"$exists":True}}]
    r = backend.find(query, _PROJECTION)
    if r.count() == 0: return False
    for i in r:
        if i["data"]["eventid"] == "cowrie.session.file_download":
            j = filt_cowrie_file_download(i, backend)
        backend.update_one( {"uuid" : i["uuid"]}, {"$addToSet": {"filters": filt_id} })
    return True
            
        

def filt_cowrie_file_download(data, backend):
    uuid = data["uuid"]
    
    data = data["data"]
    url = data['url']
    filename = url.split('/')[-1]
    sha256 = data['shasum']

    url_att = Attribute('url', url, backend=backend)
    filename_att = Attribute('filename', filename, backend=backend)
    sha256_att = Attribute('sha256', sha256, backend=backend)

    url_obj = Object('url', [url_att], backend=backend)   
    file_obj = Object('file', [filename_att, sha256_att], backend=backend)

    timestamp = data["@timestamp"]
    timestamp = dt.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp()
    e = Event('file_download', 'identity--61de9cc8-d015-4461-9b34-d2fb39f093fb',
              [url_obj, file_obj], timestamp, backend=backend)

    hostname = data['host']['name']
    hostname_att = Attribute('hostname', hostname, backend=backend)
    sessionid = data['session']
    sessionid_att = Attribute('sessionid', sessionid, backend=backend)

    session_obj = Object('session_identifier', [hostname_att, sessionid_att], backend=backend)
    session = Session('cowrie_session', session_obj, backend=backend)
    session.add_event(e)

