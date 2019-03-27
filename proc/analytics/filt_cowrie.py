import sys
sys.path.append("..")
from common.loaddb import loaddb
from common.schema.stix2ext import *
import stix2
from pprint import pprint
import time

db = loaddb('archive')
coll = db.events

_ANALYTICS_ORGID = "63476b91-c478-42b6-a554-a32b02836dc0"
_EIDS = ['cowrie.direct-tcpip.request', 'cowrie.login.failed', 'cowrie.session.closed', 'cowrie.client.kex', 'cowrie.client.version', 'cowrie.session.connect', 'cowrie.login.success', 'cowrie.direct-tcpip.data', 'cowrie.command.input', 'cowrie.command.success', 'cowrie.command.failed', 'cowrie.session.file_download', 'cowrie.log.closed', 'cowrie.session.params', 'cowrie.session.file_download.failed', 'cowrie.client.size', 'cowrie.client.var']
    
def observed_data(time_final, orgid, objects_val):  
    import uuid
    
    oid_val = "observed-data--" + str(uuid.uuid4())
    
    first_observed_val = time_final
    last_observed_val = first_observed_val
    number_observed_val = 1
    created_by_ref_val = "identity--" + str(orgid)
    
    observedDataRegKey = stix2.ObservedData(
        id = oid_val,
        first_observed = first_observed_val,
        last_observed = last_observed_val,
        number_observed = number_observed_val,
        created_by_ref = created_by_ref_val,
        objects = objects_val,
        allow_custom = True
    )

    return observedDataRegKey


def cowrie_2_ip(din_json):
    global _ANALYTICS_ORGID

    din_stix = stix2.parse(din_json, allow_custom = True)
    try: 
        value_val = din_stix["objects"]["0"]["data"]["src_ip"]
    except KeyError:
        return None, None

    time_final = din_stix["first_observed"]
    orgid = _ANALYTICS_ORGID
    objects_val = {
                    "0" : {
                      "type" : "ipv4-addr",
                      "value" : value_val
                    }
                  }
    ovd = observed_data(time_final, orgid, objects_val)
    rel = stix2.Relationship(source_ref = ovd,
                             relationship_type = 'filtered-from',
                             target_ref = din_stix )
    return ovd, rel

def get_data_cursor(filt_id, *args, **kwargs):
    query = {
        "$and" : [
            {"objects.0.type" : "x-unr-honeypot"},
            {"filters" : { "$ne": filt_id }}
        ]
    }
    
    eventid = kwargs.pop('eventid', None)
    if eventid:
        q = {"objects.0.data.eventid":eventid}
        query["$and"].append(q)
    
    projection = {"_id":0, "filters":0, "baddata":0}
    new_data = coll.find(query, projection)
    return new_data

def filt_cowrie_2_ip():
    filt_id = "filter--cd8b9c32-68ba-4403-82c5-df48e0fdde38"
    new_data = get_data_cursor(filt_id)
    
    if new_data.count() == 0 : return False
    
    for din_json in new_data:
        ovd, rel = cowrie_2_ip(din_json)
        if ovd:
            i1 = coll.insert([dict(ovd), dict(rel)])
            i2 = coll.update(
               {"id" : din_json["id"]},
               { "$push": { "filters": filt_id } }
            )
            return True

def remove_dup_ip():
    """ If two ipv4-addr objects have same value remove one,
    replace all of its references"""
    pass

def cowrie_session_file_download_2_url(din_json):
    global _ANALYTICS_ORGID

    din_stix = stix2.parse(din_json, allow_custom = True)
    try: 
        value_val = din_stix["objects"]["0"]["data"]["url"]
    except KeyError:
        return None, None

    time_final = din_stix["first_observed"]
    orgid = _ANALYTICS_ORGID
    objects_val = {
                    "0" : {
                      "type" : "url",
                      "value" : value_val
                    }
                  }
    ovd = observed_data(time_final, orgid, objects_val)
    rel = stix2.Relationship(source_ref = ovd,
                             relationship_type = 'filtered-from',
                             target_ref = din_stix )
    return ovd, rel    

def cowrie_session_file_download_2_file(din_json):
    global _ANALYTICS_ORGID

    din_stix = stix2.parse(din_json, allow_custom = True)
    try: 
        SHA_256_val = din_stix["objects"]["0"]["data"]["shasum"]
    except KeyError:
        return None, None
    url = din_stix["objects"]["0"]["data"]["url"]
    name_val = url.split('/')[-1]
    
    time_final = din_stix["first_observed"]
    orgid = _ANALYTICS_ORGID
    objects_val = {
                      "0": {
                        "type": "file",
                        "hashes": {
                          "SHA-256": SHA_256_val
                        },
                        "name": name_val
                      }
                    }
    ovd = observed_data(time_final, orgid, objects_val)
    rel = stix2.Relationship(source_ref = ovd,
                             relationship_type = 'filtered-from',
                             target_ref = din_stix )
    return ovd, rel
def relate_object_2_ip(ovd, rel):
    """ what if ip relation not exists"""
    
    target_ref = rel["target_ref"]
    all_rels = coll.find({"target_ref" : target_ref})
    for ip_rel in all_rels:
        source_ref = ip_rel["source_ref"]
        query = {
            "$and" : [
                {"id" : source_ref},
                {"objects.0.type":"ipv4-addr"}
            ]
        }        
        ipv4_obj = coll.find_one(query)
        if ipv4_obj: break
    reloi = stix2.Relationship(source_ref = ipv4_obj["id"],
                               relationship_type = "related-to",
                               target_ref = ovd)
            
    return reloi

def filt_cowrie_session_file_download_2_file_url():
    filt_id = "filter--cb490786-19da-4f7b-b919-a33c4610349c"
    eventid = "cowrie.session.file_download"    
    new_data = get_data_cursor(filt_id, eventid=eventid)
    for din_json in new_data:
        k = din_json['objects']['0']['data'].keys()
        if 'shasum' not in k or 'url' not in k:
            i2 = coll.update_one(
               {"id" : din_json["id"]},
               { "$set": { "baddata": True } }
            )
            continue
        ovdu, reluo = cowrie_session_file_download_2_url(din_json)
        ovdf, relfo = cowrie_session_file_download_2_file(din_json)
        if None in (ovdu, ovdf): return None

        reluf = stix2.Relationship(source_ref = ovdu,
                                  relationship_type = 'downloads',
                                  target_ref = ovdf)

        reliu = relate_object_2_ip(ovdu, reluo)
        relif = relate_object_2_ip(ovdf, relfo)
        i1 = coll.insert_many([dict(ovdu), dict(reluo),
                          dict(ovdf), dict(relfo),
                          dict(reluf), dict(reliu), dict(relif)])
        i2 = coll.update_one(
           {"id" : din_json["id"]},
           { "$push": { "filters": filt_id } }
        )
        





##all_data = coll.find({"objects.0.type" : "x-unr-honeypot"},
##                     {"_id" : 0, "filters" : 0})
##
##eids = []
##for e in all_data:
##    if "eventid" in e["objects"]["0"]["data"].keys():
##        eid = e["objects"]["0"]["data"]["eventid"]
##        if eid not in eids:
##            print(eid)
##            eids.append(eid)
              
        
