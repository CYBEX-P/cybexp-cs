import os, logging, json
from tahoe import get_backend, NoBackend, Attribute, Object, Event, Session, parse

import pdb
from pprint import pprint

_PROJECTION = {"_id":0, "filters":0, "_valid":0}
_MAP_ATT = {
            "aba-rtn":"aba_rtn",
            "attachment":"filename",
            "AS":"asn",
            "bank-account-nr":"bank_ac_nr",
            "bic":"swift_bic",
            "campaign-name":"name",
            "dns-soa-email":"soa_email",
            "email-attachment":"filename",
            "email-subject":"text",
            "email-dst":"email_addr",
            "email-src":"email_addr",
            "github-repository":"url",
            "github-username":"username",
            "ip-src" : "ipv4",
            "ip-dst":"ipv4",
            "link":"url",
            "mobile-application-id":"id",
            "named pipe":"x_misp_named_pipe",
            "pattern-in-file":"data",
            "pattern-in-memory":"data",
            "pattern-in-traffic":"data",
            "pdb":"filepath",
            "phone-number":"phone_number",
            "prtn":"phone_number",
            "sigma":"text",
            "size-in-bytes":"size_bytes",
            "snort":"snort_config",
            "target-location":"country_code",
            "target-org":"organization",
            "target-external":"organization_name",
            "threat-actor":"name",
            "user-agent":"user_agent",
            "whois-creation-date":"creation_date",
            "whois-registrant-email":"registrant_email",
            "whois-registrant-name":"registrant_name",
            "whois-registrant-phone":"registrant_phone",
            "whois-registrar":"registrar",
            "windows-scheduled-task":"windows_scheduled_task",
            "windows-service-name":"windows_service_name",
            "x509-fingerprint-md5":"md5",
            "x509-fingerprint-sha1":"sha1",
            "x509-fingerprint-sha256":"sha256"}

_MAP_OBJ = {
            "aba-rtn":"bank_ac",
            "AS":"autonomous_system",
            "authentihash":"hash",
            "bank-account-nr":"bank_ac",
            "bic":"financial_institue",
            "campaign-name":"campaign",
            "dns-soa-email":"dns",
            "email-attachment":"email_attachment",
            "email-subject":"email_subject",
            "email-dst":"dst",
            "email-src":"src",
            "filename":"file",
            "github-repository":"github",
            "github-username":"github",
            "hostname":"host",
            "imphash":"hash",
            "ip-src": "src",
            "ip-dst":"dst", 
            "link":"url",
            "md5":"hash",
            "mobile-application-id":"mobile_app",
            "named pipe":"x_misp_named_pipe",
            "pattern-in-file":"file",
            "pattern-in-memory":"pattern_in_memory",
            "pattern-in-traffic":"pattern_in_traffic",
            "pehash":"file",
            "phone-number":"identity",
            "prtn":"identity",
            "regkey" : "registry",
            "sha1":"hash",
            "sha256":"hash",
            "sigma":"x_misp_sigma",
            "size-in-bytes":"size",
            "snort":"ids_config",
            "ssdeep":"hash",
            "target-external":"target",
            "target-location":"target",
            "target-org":"target",
            "threat-actor":"threat_actor",
            "user-agent":"user_agent",
            "whois-creation-date":"whois",
            "whois-registrant-email":"whois",
            "whois-registrant-name":"whois",
            "whois-registrant-phone":"whois",
            "whois-registrar":"whois",
            "windows-scheduled-task":"windows_scheduled_task",
            "windows-service-name":"windows_service",
            "x509-fingerprint-md5":"x509",
            "x509-fingerprint-sha1":"x509",
            "x509-fingerprint-sha256":"x509",
            "yara":"malware"}

def filt_misp():
    try: 
        filt_id = "filter--f2d1b00a-24fc-4faa-95aa-2932b3b400e5"
        query = {"raw_type":"x-misp-event", "filters":{"$ne": filt_id },
                 "_valid" : {"$ne" : False}}
        backend = get_backend() if os.getenv("_MONGO_URL") else NoBackend()
        cursor = backend.find(query, _PROJECTION)
        if not cursor: return False
        for raw in cursor:
##            try:
                j = Misp(raw) 
##            except:
##                logging.error("proc.analytics.filters.filt_misp.filt_misp: " \
##                    "Unknown MISP Structure: \n" + json.dumps(raw,indent=4), exc_info=True)
##                continue
    except:
        logging.error("proc.analytics.analytics: ", exc_info=True)
##        backend.update_one( {"uuid" : raw["uuid"]}, {"$set" : {"_valid" : False}})
        return False
##    else:
##        backend.update_one( {"uuid" : raw["uuid"]}, {"$addToSet": {"filters": filt_id} })
    return True

class Misp():
    def __init__(self, raw):
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

            event_id_obj = Object('id', Attribute('id', self.event.pop('id')))
            event_uuid_obj = Object('uuid', Attribute('uuid', self.event.pop('uuid')))
            info_obj = Object('info', Attribute('text', self.event.pop('info')))
            threat_level_obj = Object('threat_level', Attribute('id', self.event.pop('threat_level_id')))


            self.objects = [org_obj, orgc_obj, event_id_obj, info_obj, threat_level_obj]

            misp_attribute = self.event.pop("Attribute")

            ###############################
            print("===========================================================\n"\
                  "===========================================================\n"\
                  "===========================================================\n"\
                  "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n"\
                  "===========================================================\n")
            pprint(self.event)
            print('\n')
            pprint(misp_attribute)
            print('\n')
            ################################################
            
            for attribute in misp_attribute:
                comment_att = Attribute('comment', attribute.pop('comment'))
                category_att = Attribute('x_misp_category', attribute.pop('category'))
                uuid_att = Attribute('uuid', attribute.pop('uuid'))

                misp_type = attribute.pop("type")
                misp_value = attribute.pop("value")

                if misp_type in ['filename|md5', 'filename|sha1', 'filename|sha256']:
                    filename_type, hash_type = misp_type.split('|')
                    filename_value, hash_value = misp_value.split('|')
                    filename_att = Attribute(filename_type,filename_value)
                    hash_att = Attribute(hash_type, hash_value)
                    obj = Object('file', [filename_att, hash_att])

                elif misp_type == 'regkey|value':
                    regkey_value, value_value = misp_value.split('|')
                    regkey_att = Attribute('regkey', regkey_value)
                    value_att = Attribute('registry_value', value_value)
                    obj = Object('registry', [regkey_att, value_att])

                elif misp_type == 'malware-sample':
                    filename_value, hash_value = misp_value.split('|')
                    filename_att = Attribute('filename', filename_value)
                    hash_att = Attribute('hash', hash_value)
                    obj = Object('malware', [filename_att, hash_att])

                elif misp_type == 'ip-dst|port':
                    ipv4_val, port_val = misp_value.split('|')
                    ipv4_att = Attribute('ipv4', ipv4_val)
                    port_att = Attribute('port', port_val)
                    obj = Object('dst', [ipv4_att, port_att])

                elif misp_type == 'ip-src|port':
                    ipv4_val, port_val = misp_value.split('|')
                    ipv4_att = Attribute('ipv4', ipv4_val)
                    port_att = Attribute('port', port_val)
                    obj = Object('src', [ipv4_att, port_att])

                elif misp_type == 'domain|ip':
                    domain_val, ipv4_val = misp_value.split('|')
                    ipv4_att =  Attribute('ipv4', ipv4_val)
                    domain_att = Attribute('domain', domain)
                    obj = Object('dns', [ipv4_att, domain_att])

                else:
                    if misp_type == "AS": misp_value = int(misp_value)
                    
                    att_type =  _MAP_ATT[misp_type] if misp_type in _MAP_ATT else misp_type
                    att = Attribute(att_type, misp_value)

                    obj_type =  _MAP_OBJ[misp_type] if misp_type in _MAP_OBJ else misp_type
                    obj = Object(obj_type, [att, category_att, comment_att])

                self.objects.append(obj)

                ################################
                pprint(att.document())
                print('\n')
                pprint(obj.document())
                print('\n')
                ################################
                
            
            e = Event(self.event_type, self.orgid, self.objects, self.timestamp)

        ###################################
            pprint(e.document())
            print('\n')
            
        except:
            logging.error("Uh oh, ", exc_info=True)
            pdb.set_trace()
        ###################################



if __name__ == "__main__":
    config = { 
		"mongo_url" : "mongodb://cybexp_user:CybExP_777@134.197.21.231:27017/?authSource=admin",
		"analytics_db" : "tahoe_demo",
		"analytics_coll" : "instances"
            }
    os.environ["_MONGO_URL"] = config.pop("mongo_url")
    os.environ["_ANALYTICS_DB"] = config.pop("analytics_db", "tahoe_demo")
    os.environ["_ANALYTICS_COLL"] = config.pop("analytics_coll", "instances")

    filt_misp()
