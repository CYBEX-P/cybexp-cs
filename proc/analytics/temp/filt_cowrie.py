import sys
sys.path.append("..")
from common.loaddb import loaddb
from common.schema.stix2ext import *
import stix2, json, time
from pprint import pprint
from dateutil.parser import parse as parse_time

db = loaddb('archive')
coll = db.events
rcoll = db.events
acoll = db.analytis
analytics_coll = db.analytics

_ANALYTICS_ORGID = "identity--63476b91-c478-42b6-a554-a32b02836dc0"
_EIDS = ['cowrie.direct-tcpip.request', 'cowrie.login.failed', 'cowrie.session.closed', 'cowrie.client.kex', 'cowrie.client.version', 'cowrie.session.connect', 'cowrie.login.success', 'cowrie.direct-tcpip.data', 'cowrie.command.input', 'cowrie.command.success', 'cowrie.command.failed', 'cowrie.session.file_download', 'cowrie.log.closed', 'cowrie.session.params', 'cowrie.session.file_download.failed', 'cowrie.client.size', 'cowrie.client.var']
_QLIM = 100
_PROJECTION = {"_id":0, "filters":0, "bad_data":0}

def get_new_data(filt_id, **kwargs):    
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

    time_observed = kwargs['_time']
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
    
    i_obj = observed_data(_type='ipv4-addr', ip = ip, _time = time_o)
    u_obj = observed_data(_type='url', url = url, _time = time_o)
    f_obj = observed_data(_type='file', sha256=sha256, name = fname, _time = time_o)
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

    r = coll.insert_many(json_obj)    
    coll.update_one( {"id" : din_json["id"]}, {"$push": {"filters": filt_id} })
    
    return r

def filt_cowrie_2_ip():
    filt_id = "filter--ad8c8d0c-0b25-4100-855e-06350a59750c"

    query = {"$and":[{"objects.0.type" : "x-unr-honeypot"},
                     {"bad_data" : { "$ne": True}},
                     {"filters" : { "$ne": filt_id }},
                     {"objects.0.data.eventid" : {"$exists":True}}]}
    projection = {"id" : 1, "first_observed" : 1, "objects.0.data.src_ip" : 1,}
    r = rcoll.find(query, projection)
    if not r: return None
    
    count,t, t1 = 0, 0, time.time()
    for din_json in r:
        data = din_json["objects"]["0"]["data"]
        if "src_ip" not in data.keys():
            coll.update_one({"id" : din_json["id"]},
                            {"$set": {"bad_data": True} })

        objects = {"0":{"type": "ipv4-addr", "value" : data["src_ip"]}}
        _time = din_json["first_observed"]
        
        i_obj = stix2.ObservedData(first_observed = _time,
            last_observed = _time, number_observed = 1,
            created_by_ref = _ANALYTICS_ORGID, objects = objects)

        json_obj = json.loads(i_obj.serialize())
        json_obj["x_first_observed"] = parse_time(_time)

        r = analytics_coll.insert_one(json_obj)    
        rcoll.update_one( {"id" : din_json["id"]}, {"$push": {"filters": filt_id} })

    return True

def filt_cowrie_2_url():
    filt_id = "filter--aa5273c9-6404-49de-ad5f-47dde5a08ab6"

    query = {"$and":[{"objects.0.type" : "x-unr-honeypot"},
                     {"bad_data" : { "$ne": True}},
                     {"filters" : { "$ne": filt_id }},
                     {"objects.0.data.url" : {"$exists":True}}]}
    projection = {"id" : 1, "first_observed" : 1, "objects.0.data.url" : 1,}
    r = rcoll.find(query, projection)
    if not r: return None
    
    count,t, t1 = 0, 0, time.time()
    for din_json in r:     
        data = din_json["objects"]["0"]["data"]
##        if "url" not in data.keys():
##            rcoll.update_one( {"id" : din_json["id"]}, {"$push": {"filters": filt_id} })
##            continue

        objects = {"0":{"type": "url", "value" : data["url"]}}
        _time = din_json["first_observed"]
        
        i_obj = stix2.ObservedData(first_observed = _time,
            last_observed = _time, number_observed = 1,
            created_by_ref = _ANALYTICS_ORGID, objects = objects)

        json_obj = json.loads(i_obj.serialize())
        json_obj["x_first_observed"] = parse_time(_time)

        r = analytics_coll.insert_one(json_obj)    
        rcoll.update_one( {"id" : din_json["id"]}, {"$push": {"filters": filt_id} })

    return True









