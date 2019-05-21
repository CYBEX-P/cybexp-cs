from parse_common import *
from stix2ext import Cowrie

def parse_cowrie(line, orgid, tzname = 'UTC'):
    import json
    
    data = json.loads(line)
    time_final = data["_source"]["timestamp"]
    

    objects_val = {"0":{},"1":{}}
   
    objects_val["0"]["type"] = "ipv4-addr"
    objects_val["0"]["value"] = data["_source"]["src_ip"]
    objects_val["1"]["type"] = "cowrie"
    objects_val["1"]["eventid"] = data["_source"]["eventid"]
    objects_val["1"]["msg"] = data["_source"]["msg"]
    objects_val["1"]["src_ref"] = "0"

    opt_atts = ['command', 'shasum', 'protocol', 'username', 'password', 'url']
    cur_data = data["_source"]
    cur_atts = cur_data.keys()
    for kword in opt_atts:
        if kword in cur_atts:
            objects_val['1'][kword] = cur_data[kword]
        
    return observed_data(time_final, orgid, objects_val)

import uuid
from pprint import pprint
orgid = uuid.uuid4()

td1 = """{
  "_index": "logstash-2019.02.01",
  "_type": "doc",
  "_id": "iaVJqGgBNFJmpZ5gPtBI",
  "_version": 1,
  "_score": null,
  "_source": {
    "@version": "1",
    "command": "sh",
    "geoip": {
      "location": {
        "lat": 41.7922,
        "lon": 123.4328
      },
      "timezone": "Asia/Shanghai",
      "country_code2": "CN",
      "continent_code": "AS",
      "city_name": "Shenyang",
      "country_code3": "CN",
      "latitude": 41.7922,
      "region_code": "21",
      "ip": "123.189.79.231",
      "longitude": 123.4328,
      "country_name": "China",
      "region_name": "Liaoning"
    },
    "source": "/home/cowrie/cowrie/var/log/cowrie/cowrie.json",
    "src_ip": "123.189.79.231",
    "timestamp": "2019-02-01T08:59:56.790733Z",
    "beat": {
      "hostname": "ssh-peavine",
      "version": "6.5.4",
      "name": "ssh-peavine"
    },
    "tags": [
      "beats_input_codec_plain_applied",
      "geoip"
    ],
    "host": {
      "name": "ssh-peavine"
    },
    "eventid": "cowrie.command.input",
    "msg": "CMD: sh",
    "prospector": {
      "type": "log"
    },
    "session": "3c3ffd9dbb35",
    "offset": 150822318,
    "@timestamp": "2019-02-01T08:59:57.796Z",
    "sensor": "ssh-peavine"
  },
  "fields": {
    "@timestamp": [
      "2019-02-01T08:59:57.796Z"
    ],
    "timestamp": [
      "2019-02-01T08:59:56.790Z"
    ]
  },
  "sort": [
    1549011597796
  ]
}"""

td2 = """{
  "_index": "logstash-2019.02.01",
  "_type": "doc",
  "_id": "PKVJqGgBNFJmpZ5gOtB0",
  "_version": 1,
  "_score": null,
  "_source": {
    "@version": "1",
    "session": "73646459f027",
    "sensor": "ssh-peavine",
    "geoip": {
      "location": {
        "lat": 37.751,
        "lon": -97.822
      },
      "country_code3": "US",
      "latitude": 37.751,
      "country_code2": "US",
      "continent_code": "NA",
      "ip": "192.24.144.115",
      "longitude": -97.822,
      "country_name": "United States"
    },
    "source": "/home/cowrie/cowrie/var/log/cowrie/cowrie.json",
    "src_ip": "192.24.144.115",
    "timestamp": "2019-02-01T08:59:56.782256Z",
    "beat": {
      "hostname": "ssh-peavine",
      "version": "6.5.4",
      "name": "ssh-peavine"
    },
    "shasum": "a9b1c85a7bd78dd1112ecc75c9070ea8c53078831a17aa09ebeb287fe6e21b72",
    "tags": [
      "beats_input_codec_plain_applied",
      "geoip"
    ],
    "host": {
      "name": "ssh-peavine"
    },
    "eventid": "cowrie.session.file_download",
    "msg": "Saved redir contents with SHA-256 a9b1c85a7bd78dd1112ecc75c9070ea8c53078831a17aa09ebeb287fe6e21b72 to var/lib/cowrie/downloads/a9b1c85a7bd78dd1112ecc75c9070ea8c53078831a17aa09ebeb287fe6e21b72",
    "prospector": {
      "type": "log"
    },
    "destfile": "/tmp/.none",
    "offset": 150820967,
    "@timestamp": "2019-02-01T08:59:56.789Z",
    "url": "/tmp/.none",
    "outfile": "var/lib/cowrie/downloads/a9b1c85a7bd78dd1112ecc75c9070ea8c53078831a17aa09ebeb287fe6e21b72"
  },
  "fields": {
    "@timestamp": [
      "2019-02-01T08:59:56.789Z"
    ],
    "timestamp": [
      "2019-02-01T08:59:56.782Z"
    ]
  },
  "highlight": {
    "eventid": [
      "@kibana-highlighted-field@cowrie.session.file_download@/kibana-highlighted-field@"
    ]
  },
  "sort": [
    1549011596789
  ]
}"""

td3 = """{
  "_index": "logstash-2019.02.01",
  "_type": "doc",
  "_id": "dKVJqGgBNFJmpZ5gOtB-",
  "_version": 1,
  "_score": null,
  "_source": {
    "@version": "1",
    "geoip": {
      "location": {
        "lat": 37.751,
        "lon": -97.822
      },
      "country_code3": "US",
      "latitude": 37.751,
      "country_code2": "US",
      "continent_code": "NA",
      "ip": "192.24.144.115",
      "longitude": -97.822,
      "country_name": "United States"
    },
    "source": "/home/cowrie/cowrie/var/log/cowrie/cowrie.json",
    "src_ip": "192.24.144.115",
    "timestamp": "2019-02-01T08:59:56.786284Z",
    "beat": {
      "hostname": "ssh-peavine",
      "version": "6.5.4",
      "name": "ssh-peavine"
    },
    "shasum": "1790f4c4f17378d4e636e8145f58b21c13cead1eeaf9aee4e051e612e4ef1df1",
    "tags": [
      "beats_input_codec_plain_applied",
      "geoip"
    ],
    "host": {
      "name": "ssh-peavine"
    },
    "eventid": "cowrie.log.closed",
    "size": 8829,
    "msg": "Closing TTY Log: var/lib/cowrie/tty/1790f4c4f17378d4e636e8145f58b21c13cead1eeaf9aee4e051e612e4ef1df1 after 6 seconds",
    "ttylog": "var/lib/cowrie/tty/1790f4c4f17378d4e636e8145f58b21c13cead1eeaf9aee4e051e612e4ef1df1",
    "prospector": {
      "type": "log"
    },
    "session": "73646459f027",
    "offset": 150821570,
    "@timestamp": "2019-02-01T08:59:56.789Z",
    "duration": 6.736921072006226,
    "sensor": "ssh-peavine"
  },
  "fields": {
    "@timestamp": [
      "2019-02-01T08:59:56.789Z"
    ],
    "timestamp": [
      "2019-02-01T08:59:56.786Z"
    ]
  },
  "sort": [
    1549011596789
  ]
}"""

td4 = """{
  "_index": "logstash-2019.02.01",
  "_type": "doc",
  "_id": "cqVJqGgBNFJmpZ5gOtB-",
  "_version": 1,
  "_score": null,
  "_source": {
    "@version": "1",
    "geoip": {
      "location": {
        "lat": 42.8865,
        "lon": -78.8784
      },
      "timezone": "America/New_York",
      "country_code2": "US",
      "continent_code": "NA",
      "city_name": "Buffalo",
      "country_code3": "US",
      "latitude": 42.8865,
      "postal_code": "14205",
      "dma_code": 514,
      "region_code": "NY",
      "ip": "198.98.62.237",
      "longitude": -78.8784,
      "country_name": "United States",
      "region_name": "New York"
    },
    "source": "/home/cowrie/cowrie/var/log/cowrie/cowrie.json",
    "src_ip": "198.98.62.237",
    "dst_port": 2223,
    "timestamp": "2019-02-01T08:59:56.758075Z",
    "beat": {
      "hostname": "ssh-peavine",
      "version": "6.5.4",
      "name": "ssh-peavine"
    },
    "host": {
      "name": "ssh-peavine"
    },
    "tags": [
      "beats_input_codec_plain_applied",
      "geoip"
    ],
    "eventid": "cowrie.session.connect",
    "dst_ip": "192.168.1.70",
    "src_port": 58654,
    "protocol": "telnet",
    "msg": "New connection: 198.98.62.237:58654 (192.168.1.70:2223) [session: 9840b6ed507c]",
    "prospector": {
      "type": "log"
    },
    "session": "9840b6ed507c",
    "@timestamp": "2019-02-01T08:59:56.788Z",
    "offset": 150815605,
    "sensor": "ssh-peavine"
  },
  "fields": {
    "@timestamp": [
      "2019-02-01T08:59:56.788Z"
    ],
    "timestamp": [
      "2019-02-01T08:59:56.758Z"
    ]
  },
  "highlight": {
    "eventid": [
      "@kibana-highlighted-field@cowrie.session.connect@/kibana-highlighted-field@"
    ]
  },
  "sort": [
    1549011596788
  ]
}"""
