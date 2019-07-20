import os, logging, json, copy, sys, time
from tahoe import get_backend, NoBackend, Attribute, Object, Event, Session, parse

import pdb
from pprint import pprint

_PROJECTION = {"_id":0, "filters":0, "_valid":0}
_MAP_ATT = {
    "AS":["asn","autonomous_system"],
    "btc":["btc"],
    "size-in-bytes":["bytes","size"],
    "comment":["comment"],
    "cpe":["cpe"],
    "whois-creation-date":["creation_date","whois"],
    "email-body":["data","body","email"],
    "datetime":["datetime"],
    "target-external":["description","target"],
    "domain":["domain"],
    "dns-soa-email":["email_addr","statement_of_authority","dns"],
    "email-dst":["email_addr","dst","email"],
    "email-reply-to":["email_addr","reply_to","email"],
    "email-src":["email_addr","src","email"],
    "target-email":["email_addr","target"],
    "whois-registrant-email":["email_addr","registrant","whois"],
    "email-dst-display-name":["email_display_name","dst","email"],
    "email-src-display-name":["email_display_name","src","email"],
    "attachment":["filename","file"],
    "email-attachment":["filename","attachment","email"],
    "filename":["filename","file"],
    "hex":["hex_data"],
    "hostname":["hostname"],
    "campaign-id":["id","campaign"],
    "vulnerability":["cve_id"],
    "imphash":["imphash","file"],
    "ip-dst":["ipv4","dst"],
    "ip-src":["ipv4","src"],
    "target-location":["location","target"],
    "target-machine":["machine_name","target"],
    "md5":["md5"],
    "x509-fingerprint-md5":["md5","fingerprint","x509"],
    "email-message-id":["message_id","email"],
    "email-mime-boundary":["mime_boundary","email"],
    "mobile-application-id":["mobile_app_id","mobile_app"],
    "mutex":["mutex"],
    "campaign-name":["name","campaign"],
    "target-org":["name","organization","target"],
    "target-user":["name","user","target"],
    "threat-actor":["name","threat_actor"],
    "whois-registrant-name":["name","registrant","whois"],
    "named":["pipe ","named_pipe"],
    "github-organisation":["organization"],
    "whois-registrant-org":["organization","registrant","whois"],
    "other":["other"],
    "pattern-in-file":["pattern","file"],
    "pattern-in-memory":["pattern","memory"],
    "pattern-in-traffic":["pattern","traffic"],
    "pdb":["pdb","file"],
    "pehash":["pehash","file"],
    "whois-registrant-phone":["phone","registrant","whois"],
    "phone-number":["phone_number"],
    "port":["port"],
    "prtn":["premium_rate_telephone_number"],
    "whois-registrar":["registrar","whois"],
    "regkey":["regkey","win_registry"],
    "github-repository":["repository"],
    "sha1":["sha1"],
    "x509-fingerprint-sha1":["sha1","fingerprint","x509"],
    "sha224":["sha224"],
    "sha256":["sha256"],
    "x509-fingerprint-sha256":["sha256","fingerprint","x509"],
    "sha384":["sha384"],
    "sha512":["sha512"],
    "sha512/224":["sha512/224"],
    "sha512/256":["sha512/256"],
    "sigma":["sigma","cti_analysis"],
    "snort":["snort","cti_analysis"],
    "ssdeep":["ssdeep"],
    "email-subject":["subject","email"],
    "text":["text"],
    "uri":["uri"],
    "link":["url","external_information"],
    "url":["url"],
    "user-agent":["user_agent","http"],
    "github-username":["username"],
    "jabber-id":["username","jabber"],
    "twitter-id":["username","twitter"],
    "windows-scheduled-task":["win_scheduled_task"],
    "windows-service-displayname":["win_service_displayname"],
    "windows-service-name":["win_service_name"],
    "email-x-mailer":["x_mailer","email"],
    "yara":["yara","cti_analysis"],
}

_MAP_SPLIT = {
    "filename|authentihash":["filename","authentihash"],
    "malware-sample":["filename","hash","malware"],
    "filename|impfuzzy":["filename","impfuzzy","file"],
    "filename|imphash":["filename","imphash","file"],
    "filename|md5":["filename","md5","file"],
    "filename|pehash":["filename","pehash","file"],
    "filename|sha1":["filename","sha1","file"],
    "filename|sha224":["filename","sha224","file"],
    "filename|sha256":["filename","sha256","file"],
    "filename|sha384":["filename","sha384","file"],
    "filename|sha512":["filename","sha512","file"],
    "filename|sha512/224":["filename","sha512/224","file"],
    "filename|sha512/256":["filename","sha512/256","file"],
    "filename|ssdeep":["filename","ssdeep","file"],
    "filename|tlsh":["filename","tlsh","file"],
    "regkey|value":["regkey","regdata","win_registry"],
    "domain|ip":["domain","ipv4"]
}

def filt_misp():
    try: 
        filt_id = "filter--f2d1b00a-24fc-4faa-95aa-2932b3b400e5"
        query = {"raw_type":"x-misp-event", "filters":{"$ne": filt_id },
                 "_valid" : {"$ne" : False}}
        backend = get_backend() if os.getenv("_MONGO_URL") else NoBackend()
        cursor = backend.find(query, _PROJECTION, no_cursor_timeout=True)
        if not cursor: return False
        all_types = {}
        for raw in cursor:
            try:
                j = Misp(raw, backend) 
            except:
                logging.error("proc.analytics.filters.filt_misp.filt_misp: " \
                    "Unknown MISP Structure: \n" + json.dumps(raw,indent=4), exc_info=True)
                continue
    except:
        logging.error("proc.analytics.analytics: ", exc_info=True)
##        backend.update_one( {"uuid" : raw["uuid"]}, {"$set" : {"_valid" : False}})
        return False
##    else:
##        backend.update_one( {"uuid" : raw["uuid"]}, {"$addToSet": {"filters": filt_id} })
    return True

class Misp():    
    def __init__(self, raw, backend):
        try:
            
            self.raw, self.event, self.event_type = raw, raw["data"]["Event"], 'misp'
            self.orgid, self.timestamp = self.raw.pop("orgid"), float(self.event.pop("timestamp"))

            org_id_att = Attribute('id', self.event['Org'].pop('id'))
            org_name_att = Attribute('name', self.event['Org'].pop('name'))
            org_uuid_att = Attribute('uuid', self.event['Org'].pop('uuid'))
            org_obj = Object("x_misp_org", [org_id_att, org_name_att, org_uuid_att])

            orgc_id_att = Attribute('id', self.event['Orgc']['id'])
            orgc_name_att = Attribute('name', self.event['Orgc'].pop('name'))
            orgc_uuid_att = Attribute('uuid', self.event['Orgc'].pop('uuid'))
            orgc_obj = Object("x_misp_orgc", [org_id_att, org_name_att, org_uuid_att])

            event_id_att = Attribute('id', self.event.pop('id'))
            event_uuid_obj = Object('uuid', Attribute('uuid', self.event.pop('uuid')))
            info_obj = Object('info', Attribute('text', self.event.pop('info')))
            threat_level_obj = Object('threat_level', Attribute('id', self.event.pop('threat_level_id')))



            self.objects = [org_obj, orgc_obj, event_id_att, info_obj, threat_level_obj]

            misp_attribute = self.event.pop("Attribute")
            
            for attribute in misp_attribute:
                comment_att = Attribute('comment', attribute.pop('comment'))
                category_att = Attribute('x_misp_category', attribute.pop('category'))
                uuid_att = Attribute('uuid', attribute.pop('uuid'))

                misp_type = attribute.pop("type")
                misp_value = attribute.pop("value")

                av1, av2 = self.split_attribute(misp_type, misp_value)
                if av1:
                    obj1 = self.create_att_obj(av1[0], av1[1])
                    obj2 = self.create_att_obj(av2[0], av2[1])
                    obj = [obj1,obj2]
                else:
                    type_list = _MAP_ATT[misp_type]
                    obj = [self.create_att_obj(copy.deepcopy(type_list), misp_value)]
                self.objects += obj

            t1 = time.time()
            e = Event(self.event_type, self.objects, self.orgid, self.timestamp)
            rid = [i["id"] for i in e.data if 'id' in i.keys()]
            t2 = time.time()

            print(t2-t1)
            
            eid = rid[0]
            for s in backend.find({"itype":"session","data.x_misp_related_events.x_misp_event_id":eid}):
                s = parse(s,backend,False)
                s.add_event(e)

            self.related = self.event["RelatedEvent"]
            for re in self.related: rid.append(re['Event']['id'])

            ratt = [Attribute("x_misp_event_id", i) for i in rid]
            robj = Object("x_misp_related_events", ratt)
            t1 = time.time()
            s = Session("misp_session", robj)
            t2 = time.time()
            print(t2-t1)
            s.add_event(e)
            
            
        except:
            logging.error("Uh oh, ", exc_info=True)
        ###################################
            
    def create_att_obj(self, type_list, data):
        previous = Attribute(type_list.pop(0), data)
        while type_list: previous = Object(type_list.pop(0), previous)
        return previous

    def split_attribute(self, att, value):
        if att not in _MAP_SPLIT: return None, None
        t = _MAP_SPLIT[att]
        t1, t2 = [t[0]]+t[2:], [t[1]]+t[2:]
        v1, v2 = value.split('|')
        return (t1,v1),(t2,v2)


if __name__ == "__main__":
    config = { 
##		"mongo_url" : "mongodb://cybexp_user:CybExP_777@134.197.21.231:27017/?authSource=admin",
                "mongo_url" : "mongodb://localhost:27017",
		"analytics_db" : "tahoe_demo",
		"analytics_coll" : "instances"
            }
    os.environ["_MONGO_URL"] = config.pop("mongo_url")
    os.environ["_ANALYTICS_DB"] = config.pop("analytics_db", "tahoe_demo")
    os.environ["_ANALYTICS_COLL"] = config.pop("analytics_coll", "instances")

    filt_misp()
