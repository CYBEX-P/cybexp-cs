import os, logging, json, copy, time, pdb

if __name__ == "__main__": from demo_env import *

from tahoe import get_backend, NoBackend, Attribute, Object, Event, Session, parse


_PROJECTION = {"_id":0, "filters":0, "_valid":0}


{
    "_id" : ObjectId("5d659d48148205ab44b48161"),
    "itype" : "raw",
    "data" : {
        "phish_id" : "6176706",
        "url" : "https://enqiu.ga/doo/enterpassword.php?4Hb73J15669355823f476395fe789b6e359947a34ef3236a3f476395fe789b6e359947a34ef3236a3f476395fe789b6e359947a34ef3236a3f476395fe789b6e359947a34ef3236a3f476395fe789b6e359947a34ef3236a&AP___=email@test.com&error=",
        "phish_detail_url" : "http://www.phishtank.com/phish_detail.php?phish_id=6176706",
        "submission_time" : "2019-08-27T19:53:02+00:00",
        "verified" : "yes",
        "verification_time" : "2019-08-27T19:54:35+00:00",
        "online" : "yes",
        "details" : [ 
            {
                "ip_address" : "104.18.39.113",
                "cidr_block" : "104.18.32.0/20",
                "announcing_network" : "13335",
                "rir" : "arin",
                "country" : "US",
                "detail_time" : "2019-08-27T19:54:20+00:00"
            }
        ],
        "target" : "Microsoft"
    },
    "orgid" : "identity--80093a09-afb6-47c1-8566-344c9e605c8b",
    "timezone" : "UTC",
    "sub_type" : "x-phishtank",
    "_hash" : "e984a869068d7ab84307f836c9be19b2ab999ac7ebffb32b0857ac61f8f27b62",
    "uuid" : "raw--d08c77da-9a36-4d03-9955-9a5b2a65fda5"
}

def filt_misp(backend=NoBackend()):
    try: 
        filt_id = "filter--8de6c198-25dd-4c1f-9eb9-6b6d5c3e54a6"
        if os.getenv("_MONGO_URL"): backend = get_backend()

        query = {"itype":"raw", "sub_type":"x-misp-event",
                 "filters":{"$ne":filt_id}, "_valid":{"$ne":False}}
        cursor = backend.find(query, _PROJECTION, no_cursor_timeout=True)

        any_success = False
        for raw in cursor:           
            try: j = Misp(copy.deepcopy(raw), backend)
            except:
                logging.error("proc.analytics.filters.filt_misp.filt_misp 1: " \
                    "MISP Event id " + raw["data"]["Event"]["id"], exc_info=True)
##                backend.update_one( {"uuid" : raw["uuid"]}, {"$set" : {"_valid" : False}})
                j = False
            else:
                backend.update_one( {"uuid" : raw["uuid"]}, {"$addToSet": {"filters": filt_id} })
            any_success = any_success or bool(j)
            
    except (KeyboardInterrupt, SystemExit): raise
    except:
        logging.error("proc.analytics.filters.filt_misp.filt_misp.2: ", exc_info=True)
        return False
    return any_success


class Misp():       
    def __init__(self, raw, backend):
        event_type = 'sighting'
        data = url_att
        orgid = get from data
        timestamp = (convert it to float)
        malicious = True
    

if __name__ == "__main__": filt_misp()
 
