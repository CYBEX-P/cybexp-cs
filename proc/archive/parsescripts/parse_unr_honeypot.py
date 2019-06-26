# proc\parsescriipts\parse_cowrie.py
import json, pdb, logging
from datetime import datetime as dt
from tahoe import Attribute, Object, Event

logging.basicConfig(level=logging.DEBUG)

class UnrHoneypot():
    def __init__(self, data, orgid, tzname):
        try: timestamp = data["@timestamp"]
        except KeyError:
            self.bad_data = True
            return None
        self.timestamp = dt.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp()
    
        self.orgid = orgid
        e = Event(self.event_type, self.orgid, self.object, self.timestamp)
        self.event = [e]
        

class Cowrie(UnrHoneypot):
    def __init__(self, data, orgid, tzname):
        super().__init__(data, orgid, tzname)
        

class CowrieSessionFileDownload(Cowrie):
    def __init__(self, data, orgid, tzname):
        self.bundle = []

        self.event_type = 'file_download'
        
        url = data['url']
        filename = url.split('/')[-1]
        sha256 = data['shasum']

        url_att = Attribute('url', url)
        filename_att = Attribute('filename', filename)
        sha256_att = Attribute('sha256', sha256)
        self.attribute = [url_att, filename_att, sha256_att]
        
        url_obj = Object('url', [url_att])   
        file_obj = Object('file', [filename_att, sha256_att])
        self.object = [url_obj, file_obj]

        super().__init__(data, orgid, tzname)

def parse_unr_honeypot(line, orgid, tzname = 'UTC'):
    data = json.loads(line)

    # Cowrie
    if 'eventid' in data.keys():
        eventid = data['eventid']
        if eventid == 'cowrie.session.file_download':
            e = CowrieSessionFileDownload(data, orgid, tzname)
        else:
            logging.debug('Unknown eventid')
    else:
        logging.debug('Unknown data format')
            
        

    pdb.set_trace()
        
    return None


##j = r"""{
##    "sensor" : "ssh-peavine",
##    "@timestamp" : "2019-03-06T06:46:28.515Z",
##    "geoip" : {
##        "country_code2" : "US",
##        "location" : {
##            "lat" : 37.3501,
##            "lon" : -121.9854
##        },
##        "region_code" : "CA",
##        "postal_code" : "95051",
##        "timezone" : "America/Los_Angeles",
##        "continent_code" : "NA",
##        "city_name" : "Santa Clara",
##        "longitude" : -121.9854,
##        "ip" : "165.227.0.144",
##        "country_name" : "United States",
##        "dma_code" : 807,
##        "latitude" : 37.3501,
##        "region_name" : "California",
##        "country_code3" : "US"
##    },
##    "host" : {
##        "name" : "ssh-peavine"
##    },
##    "session" : "619c9c48b812",
##    "@version" : "1",
##    "eventid" : "cowrie.session.file_download",
##    "timestamp" : "2019-03-06T06:46:27.400128Z",
##    "src_ip" : "165.227.0.144",
##    "outfile" : "var/lib/cowrie/downloads/bf69f4219069098da61a80641265d8834b474474957742510105d70703ebdb27",
##    "beat" : {
##        "version" : "6.5.4",
##        "name" : "ssh-peavine",
##        "hostname" : "ssh-peavine"
##    },
##    "tags" : [ 
##        "beats_input_codec_plain_applied", 
##        "geoip", 
##        "beats_input_codec_json_applied"
##    ],
##    "shasum" : "bf69f4219069098da61a80641265d8834b474474957742510105d70703ebdb27",
##    "prospector" : {
##        "type" : "log"
##    },
##    "msg" : "Downloaded URL (http://165.227.0.144:80/bins/rift.x86) with SHA-256 bf69f4219069098da61a80641265d8834b474474957742510105d70703ebdb27 to var/lib/cowrie/downloads/bf69f4219069098da61a80641265d8834b474474957742510105d70703ebdb27",
##    "source" : "/home/cowrie/cowrie/var/log/cowrie/cowrie.json",
##    "offset" : 23030686,
##    "url" : "http://165.227.0.144:80/bins/rift.x86",
##    "destfile" : "-"
##}"""
##
##parse_unr_honeypot(j, 'identity--875cc2fd-639e-44a6-bf3c-2837d2428438')
