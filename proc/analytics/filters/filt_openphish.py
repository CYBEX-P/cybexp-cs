import os, logging, time #, pdb
from copy import deepcopy
from datetime import datetime as dt
#import json

if __name__ == "__main__": from demo_env import *
    
from tahoe import get_backend, NoBackend, Attribute, Event, parse, UrlObejct #, Object, Session

_PROJECTION = {"_id":0, "filters":0, "_valid":0}

def filt_openphish(backend=NoBackend()):
    try: 
        filt_id = "filter--67a062dd-a6ba-45b2-b93a-1a9de9e9682b"
        if os.getenv("_MONGO_URL"): backend = get_backend()
        
        query = {"itype":"raw", "sub_type":"x-openphish",
                 "filters":{"$ne":filt_id}, "_valid" : {"$ne" : False},
                 "data":{"$exists":True},
                 "data.timestamp":{"$exists":True},
                 "data.openphish_type":{"$exists":True}}
        cursor = backend.find(query, _PROJECTION, no_cursor_timeout=True)
        if not cursor: logging.error("filt_openphish: This should not happen")

        any_success = False
        for raw in cursor:
            try:
                urls = raw["data"]["URLs"]
                timestamp = raw["data"]["timestamp"]
                openphish_type = raw["data"]["openphish_type"]

                if openphish_type == "community":
                    j = OpenPhish_Community(raw)
                # else if openphish_type == "premium":
                #     j = OpenPhish_Premium(raw)
                else:
                    j = False

            except (KeyboardInterrupt, SystemExit): raise
            except:
                logging.error("\nfilt_openphish.filt_main 1: uuid: {}\n".format(raw["uuid"]), exc_info=True)
                              #", timestamp: " + timestamp + "\n", exc_info=True)
##                backend.update_one( {"uuid" : raw["uuid"]}, {"$set" : {"_valid" : False}})
                j = False
            else: 
                backend.update_one({"uuid":raw["uuid"]}, {"$addToSet":{"filters":filt_id}})
            any_success = any_success or bool(j)

    except:
        logging.error("filt_openphish.filt_main 2: ", exc_info=True)
        return False
    return any_success


class OpenPhish():
    def __init__(self):
        #print("openphish.super()")
        raw = parse(self.raw)

        evnt_uuids = [evnt.uuid for evnt in self.event_list]
        evnts_relateds = list()
        for evnt in self.event_list:
            evnts_relateds += evnt.related_uuid()
       
        ref_uuid_list =  evnt_uuids + evnts_relateds
        ref_uuid_list = list(set(ref_uuid_list)) # dedupplicate
        raw.update_ref(ref_uuid_list)



class OpenPhish_Community(OpenPhish):
    def __init__(self, raw):
        #print("crating comunity")
        self.orgid = raw["orgid"]
        self.event_type = 'sighting'
        #print("OG RAW:", raw)
        self.raw_data, self.raw = raw.pop("data"), raw
        self.timestamp = self.raw_data["timestamp"]

        urlobject_list = [UrlObject(url, malicious=True, source="openphish") for url in self.raw_data["URLs"]]
        event_list = list()

        for uo in urlobject_list:
            event_list.append(Event(self.event_type, [uo], self.orgid, self.timestamp, malicious=True, mal_data=[uo] ))


        self.event_list = event_list
        super().__init__()










############################################
########### NOT FINISHED ###################
########### NOT TESTED #####################
############################################

# class OpenPhish_Premium(OpenPhish):
#     def __init__(self, raw):
#         self.orgid = raw["orgid"]
#         self.event_type = 'openphish_url'
#         self.raw_data, self.raw = raw.pop("data"), raw

#         event_list = list()
#         for url_data in self.raw_data:
#             attr_list = list()
#             mal_data = list()
#             timestamp = 0
#             for data_attr_key in url_data:
#                 if data_attr_key == "isotime":
#                     timestamp = dt.fromisoformat(url_data[data_attr_key].replace("Z", "+00:00")).timestamp()
#                 atrib = Attribute(data_attr_key, url_data[data_attr_key])
#                 attr_list.sppend(atrib)
#                 if isMalicious(data_attr_key):
#                     mal_data.append(atrib)
#             event_list.append(Event(self.event_type, attr_list, self.orgid, timestamp, malicious=True, mal_data=mal_data))


#         self.event_list = event_list
#         super().__init__()


# def isMalicious(test_str):
#     mal = ["url"]
#     return test_str in mal



##if __name__ == "__main__":
##    config = { 
##      "mongo_url" : "mongodb://cybexp_user:CybExP_777@134.197.21.231:27017/?authSource=admin",
##                "mongo_url" : "mongodb://localhost:27017/",
##      "analytics_db" : "tahoe_db",
##      "analytics_coll" : "instances"
##            }
##    
##    os.environ["_MONGO_URL"] = config.pop("mongo_url")
##    os.environ["_TAHOE_DB"] = config.pop("analytics_db", "tahoe_db")
##    os.environ["_TAHOE_COLL"] = config.pop("analytics_coll", "instances")
##    
##    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s:%(message)s') 
##
##    filt_openphish()    


    

