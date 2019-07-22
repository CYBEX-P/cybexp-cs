import os, logging, json, copy, sys, time
from tahoe import get_backend, NoBackend, Attribute, Object, Event, Session, parse

import pdb
from pprint import pprint

_PROJECTION = {"_id":0, "filters":0, "_valid":0}
_MAP_ATT = {
    "AS":["asn","autonomous_system"],
    "attachment":["filename","file"],
    "btc":["btc"],
    "campaign-id":["id","campaign"],
    "campaign-name":["name","campaign"],
    "comment":["comment"],
    "cpe":["cpe"],
    "datetime":["datetime"],
    "dns-soa-email":["email_addr","statement_of_authority","dns"],
    "domain":["domain"],
    "email-attachment":["filename","attachment","email"],
    "email-body":["data","body","email"],
    "email-dst":["email_addr","dst","email"],
    "email-dst-display-name":["email_display_name","dst","email"],
    "email-message-id":["message_id","email"],
    "email-mime-boundary":["mime_boundary","email"],
    "email-reply-to":["email_addr","reply_to","email"],
    "email-src":["email_addr","src","email"],
    "email-src-display-name":["email_display_name","src","email"],
    "email-subject":["subject","email"],
    "email-x-mailer":["x_mailer","email"],
    "filename":["filename","file"],
    "github-organisation":["organization"],
    "github-repository":["repository"],
    "github-username":["username"],
    "hex":["hex_data"],
    "hostname":["hostname"],
    "imphash":["imphash","file"],
    "ip-dst":["ipv4","dst"],
    "ip-src":["ipv4","src"],
    "jabber-id":["username","jabber"],
    "link":["url","external_information"],
    "md5":["md5"],
    "mobile-application-id":["mobile_app_id","mobile_app"],
    "mutex":["mutex"],
    "named pipe":["named_pipe"],
    "other":["other"],
    "pattern-in-file":["pattern","file"],
    "pattern-in-memory":["pattern","memory"],
    "pattern-in-traffic":["pattern","traffic"],
    "pdb":["pdb","file"],
    "pehash":["pehash","file"],
    "phone-number":["phone_number"],
    "port":["port"],
    "prtn":["premium_rate_telephone_number"],
    "regkey":["regkey","win_registry"],
    "sha1":["sha1"],
    "sha224":["sha224"],
    "sha256":["sha256"],
    "sha384":["sha384"],
    "sha512":["sha512"],
    "sha512/224":["sha512/224"],
    "sha512/256":["sha512/256"],
    "sigma":["sigma","cti_analysis"],
    "size-in-bytes":["bytes","size"],
    "snort":["snort","cti_analysis"],
    "ssdeep":["ssdeep"],
    "target-email":["email_addr","target"],
    "target-external":["description","target"],
    "target-location":["location","target"],
    "target-machine":["machine_name","target"],
    "target-org":["name","organization","target"],
    "target-user":["name","user","target"],
    "text":["text"],
    "threat-actor":["name","threat_actor"],
    "twitter-id":["username","twitter"],
    "uri":["uri"],
    "url":["url"],
    "user-agent":["user_agent","http"],
    "vulnerability":["cve_id"],
    "whois-creation-date":["creation_date","whois"],
    "whois-registrant-email":["email_addr","registrant","whois"],
    "whois-registrant-name":["name","registrant","whois"],
    "whois-registrant-org":["organization","registrant","whois"],
    "whois-registrant-phone":["phone","registrant","whois"],
    "whois-registrar":["registrar","whois"],
    "windows-scheduled-task":["win_scheduled_task"],
    "windows-service-displayname":["win_service_displayname"],
    "windows-service-name":["win_service_name"],
    "x509-fingerprint-md5":["md5","fingerprint","x509"],
    "x509-fingerprint-sha1":["sha1","fingerprint","x509"],
    "x509-fingerprint-sha256":["sha256","fingerprint","x509"],
    "yara":["yara","cti_analysis"],
}

_MAP_SPLIT = {
    "domain|ip":["domain","ipv4"],
    "filename|authentihash":["filename","authentihash"],
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
    "ip-dst|port":["ipv4","port","dst"],
    "ip-src|port":["ipv4","port","src"],
    "hostname|port":["hostname","port","host"],
    "malware-sample":["filename","hash","malware"],
    "regkey|value":["regkey","regdata","win_registry"]
}

_ALIAS = {
    "misp att" : ["misp alias"],
    "campaign-id" : ["campaign_id"],
    "campaign-name" : ["campaign_name"],
    "dns-soa-email" : ["dns_soa_email"],
    "email-attachment" : ["email_attachment_name"],
    "email-body" : ["email_body	"],
    "email-reply-to" : ["email_reply_to"],
    "pattern-in-file" : ["pattern_in_file"],
    "pattern-in-memory" : ["pattern_in_file"],
    "pattern-in-traffic" : ["pattern_in_file"],
    "target-external" : ["target_name, x_misp_target_external"],
    "target-location" : ["x_misp_target_location"],
    "target-org" : ["target_name, x_misp_target_org"],
    "target-user" : ["target_name, x_misp_target_user"],
    "threat-actor" : ["threat_actor_name"]
}

def filt_misp():
    try: 
        filt_id = "filter--f2d1b00a-24fc-4faa-95aa-2932b3b400e5"
        query = {"raw_type":"x-misp-event", "filters":{"$ne":filt_id}, "_valid":{"$ne":False}}
        backend = get_backend() if os.getenv("_MONGO_URL") else NoBackend()

        cursor = backend.find(query, _PROJECTION, no_cursor_timeout=True)
        if not cursor: return False
        for raw in cursor:
            try:
                j = Misp(raw, backend)
            except:
                logging.error("proc.analytics.filters.filt_misp.filt_misp.1: " \
                    "Unknown MISP Structure: \n MISP Event id" + raw["data"]["Event"]["id"], exc_info=True)
    except:
        logging.error("proc.analytics.filters.filt_misp.filt_misp.2: ", exc_info=True)
            backend.update_one( {"uuid" : raw["uuid"]}, {"$set" : {"_valid" : False}})
        return False
        else:
            backend.update_one( {"uuid" : raw["uuid"]}, {"$addToSet": {"filters": filt_id} })
    return True


class MispAttribute(Attribute):
    def __init__(self, *args, **kwargs):
        super().__init__(alias = _ALIAS.get(args[0],[]), *args, **kwargs)


class Misp():       
    def __init__(self, raw, backend):
        e = raw["data"]["Event"]
        attribute, related = e["Attribute"], e["RelatedEvent"]
        event_type, orgid, timestamp = 'misp', raw["orgid"], float(e["timestamp"])

        t1 = time.time()
        org, orgc = self.parse_org(e['Org']), self.parse_org(e['Orgc'])
        t2 = time.time()
        eid, euuid = MispAttribute('id', e['id']), MispAttribute('uuid', e['uuid'])
        t3 = time.time()
        info = MispAttribute('info', e['info'])
        t4 = time.time()
        threat_level = MispAttribute('x_misp_threat_level_id', e['threat_level_id'])
        t5 = time.time()
        data = [org, orgc, eid, euuid, info, threat_level]

        print("%.2f\t%.2f\t%.2f\t%.2f" % (t2-t1,t3-t2,t4-t3,t5-t4))

        t1 = time.time()
        for att in attribute:
            comment = MispAttribute('comment', att['comment'])
            category = MispAttribute('x_misp_category', att['category'])
            uuid = MispAttribute('uuid', att['uuid'])

            t, v = att['type'], att['value']
            av1, av2 = self.split_attribute(t, v)
            if av1:
                obj1 = self.create_att_obj(av1[0], av1[1])
                obj2 = self.create_att_obj(av2[0], av2[1])
                obj = [obj1,obj2]
            else:
                type_list = _MAP_ATT[t]
                obj = [self.create_att_obj(copy.deepcopy(type_list), v)]
            data += obj
##        print(time.time() - t1)

        t1 = time.time()
        event = Event(event_type, data, orgid, timestamp)
##        print(time.time() - t1)

        rid = event.data['id']
        eid = rid[0]
        t1 = time.time()
        for s in backend.find({"itype":"session", "data.x_misp_related_events.x_misp_event_id":eid}):
            s = parse(s, backend, False)
            s.add_event(event)
        t2 = time.time()
##        print(t2-t1)

        for re in related: rid.append(re['Event']['id'])
        ratt = [MispAttribute("x_misp_event_id", i) for i in rid]
        t1 = time.time()
        s = Session("misp_session", ratt)
        t2  = time.time()
        s.add_event(event)
        t3 = time.time()
##        print(t2-t1)
##        print(t3-t2)
        

    def create_att_obj(self, type_list, data):
        previous = MispAttribute(type_list.pop(0), data)
        while type_list: previous = Object(type_list.pop(0), previous)
        return previous

    def parse_org(self, org):
        oid = MispAttribute('id', org['name'])
        oname = MispAttribute('name', org['name'])
        ouuid = MispAttribute('uuid', org['uuid'])
        return Object('x_misp_org', [oid, oname, ouuid])

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
##		"analytics_db" : "tahoe_db",
                "analytics_db" : "tahoe_demo",
		"analytics_coll" : "instances"
            }
    os.environ["_MONGO_URL"] = config.pop("mongo_url")
    os.environ["_ANALYTICS_DB"] = config.pop("analytics_db", "tahoe_db")
    os.environ["_ANALYTICS_COLL"] = config.pop("analytics_coll", "instances")

    filt_misp()
