import sys
sys.path.append("..")
from common.loaddb import loaddb
from common.schema.stix2ext import *
import stix2, json, time
from pprint import pprint

db = loaddb('archive')
coll = db.events

_ANALYTICS_ORGID = "identity--63476b91-c478-42b6-a554-a32b02836dc0"
_EIDS = ['cowrie.direct-tcpip.request', 'cowrie.login.failed', 'cowrie.session.closed', 'cowrie.client.kex', 'cowrie.client.version', 'cowrie.session.connect', 'cowrie.login.success', 'cowrie.direct-tcpip.data', 'cowrie.command.input', 'cowrie.command.success', 'cowrie.command.failed', 'cowrie.session.file_download', 'cowrie.log.closed', 'cowrie.session.params', 'cowrie.session.file_download.failed', 'cowrie.client.size', 'cowrie.client.var']
_QLIM = 100
_PROJECTION = {"_id":0, "filters":0, "bad_data":0}

def get_new_data(filt_id, *args, **kwargs):    
    query = {"$and":[{"objects.0.type" : "x-unr-honeypot"}, {"bad_data" : { "$ne": True}}, {"filters" : { "$ne": filt_id }}, { "objects.0.data.eventid" : {"$exists":True}}]}

    eventid = kwargs.pop('eventid', None)
    if eventid: query["$and"].append({"objects.0.data.eventid" : eventid})
    
    new_data = coll.find_one(query, _PROJECTION)
    return new_data

    
def valid_cowrie_data(din_json, req_keys):
    if not din_json: return None

    dat_keys = din_json['objects']['0']['data'].keys()
    for k in req_keys:
        if k not in dat_keys: 
            coll.update_one({"id" : din_json["id"]}, {"$set": {"bad_data": True} })
            return False
    return True

def json_2_query_list(val, old = ""):
    dota = []
    if isinstance(val, dict):
        for k in val.keys():
            dota += json_2_query_list(val[k], old + str(k) + ".")
##    elif isinstance(val, list):
##        for k in val:
##            dota += json_2_query_list(k, old  )
    else: dota = [{old[:-1] : val}]
    return dota  

def duplicate(obj):
    match_keys = ['type', 'objects', 'source_ref', 'target_ref']

    obj = json.loads(obj.serialize())

    rem_keys = [k for k in obj.keys() if k not in match_keys]
    for k in rem_keys: obj.pop(k)

    query = {"$and" : json_2_query_list(obj)}
    return coll.find_one(query, _PROJECTION)

def observed_data(*args, **kwargs):
    _type = kwargs['_type']
    objects = {"0":{"type":_type}}
    if _type == 'ipv4-addr': objects['0']['value'] = kwargs['ip']
    if _type == 'url': objects['0']['value'] = kwargs['url']
    if _type == 'file':
        objects['0']['hashes'] = {"SHA-256" : kwargs['sha256']}
        objects['0']['name'] = kwargs['name']

    time_observed = kwargs['time']
    obj = stix2.ObservedData(first_observed = time_observed,
        last_observed = time_observed, number_observed = 1,
        created_by_ref = _ANALYTICS_ORGID, objects = objects)

    dup = duplicate(obj)
    if dup: return stix2.parse(dup)
    return obj
   
def filt_cowrie_session_file_download():
    filt_id = "filter--cb490786-19da-4f7b-b919-a33c4610349c"
    eventid = "cowrie.session.file_download"

    din_json = get_new_data(filt_id, eventid = eventid)

    req_keys = ['src_ip','shasum','url']
    v = valid_cowrie_data(din_json, req_keys)
    if not v: return v
    
    time_o = din_json["first_observed"]
    data = din_json["objects"]["0"]["data"]
    ip, sha256, url = data["src_ip"], data["shasum"], data["url"]
    fname = url.split('/')[-1]
    
    i_obj = observed_data(_type='ipv4-addr', ip = ip, time = time_o)
    u_obj = observed_data(_type='url', url = url, time = time_o)
    f_obj = observed_data(_type='file', sha256=sha256, name = fname, time = time_o)
    c_obj = stix2.parse(din_json, allow_custom = True)
    
    r_i_c = stix2.Relationship(i_obj, 'filtered-from', c_obj)
    r_u_c = stix2.Relationship(u_obj, 'filtered-from', c_obj)
    r_f_c = stix2.Relationship(f_obj, 'filtered-from', c_obj)
    r_i_u = stix2.Relationship(i_obj, 'related-to', u_obj)
    r_i_f = stix2.Relationship(i_obj, 'related-to', f_obj)
    r_u_f = stix2.Relationship(u_obj, 'downloads', f_obj)

    json_obj = []
    for obj in [i_obj, u_obj, f_obj, c_obj, r_i_c, r_u_c, r_f_c, r_i_u, r_i_f, r_u_f]:
        if not duplicate(obj): 
            json_obj.append(json.loads(obj.serialize()))
    import pdb
    pdb.set_trace()
    r = coll.insert_many(json_obj)    
    coll.update_one( {"id" : din_json["id"]}, {"$push": {"filters": filt_id} })
    
    return r

print(filt_cowrie_session_file_download().inserted_ids)

##def clear_all_processed_data():
##    coll.delete_many({"objects.0.type":"ipv4-addr"})
##    coll.delete_many({"objects.0.type":"file"})
##    coll.delete_many({"objects.0.type":"url"})
##    coll.delete_many({"type":"relationship"})
##    coll.update({}, {"$unset": {"filters":1}} , {"multi": True});
##


















####### 1 ###############

##q = {"$and" : [ {"type" : "observed-data"} , { "objects.0.type" : {"$ne" : "x-unr-honeypot"} } ]}
##r = coll.find(q)
##all_typs = {}
##for e in r:
##    typ = e["objects"]["0"]["type"]
##    if typ in all_typs.keys():
##        all_typs[typ] += 1
##    else:
##        all_typs[typ] = 1
##print(all_typs)



########### 2 ##################
##q = {"$and" : [{"type" : "observed-data"}, {"created": {"$regex": '2019-03-29.*'}}]}
##q = {"$and" : [{"created": {"$regex": '2019-03-29.*'}}, {"objects.0.type" : "x-unr-honeypot"} ]}
##r = coll.find(q)
##all_eids = {}
##others = 0
##for e in r:
##    try:
##        eid = e["objects"]["0"]["data"]["eventid"]
##        if eid in all_eids.keys():
##            all_eids[eid] += 1
##        else:
##            all_eids[eid] = 1
##    except:
##        others += 1
##
##total = sum(all_eids.values()) + others
##
##import operator
##all_eids = sorted(all_eids.items(), reverse=True,
##                  key=operator.itemgetter(1))
##all_eids.append(('OTHERS', others))
##all_eids.append(('TOTAL', total))
##
##
##
##for k,v in all_eids:
##    print(k, ' : ', v)            

