if __name__ == "__main__":
    from views_comm import *
else:
    from .views_comm import * # .views=views.py, views=this folder

# Load Analytics Database
ancoll = coll_or_fs('analytics')

def get_count(**kwargs): 
    obj_typ = kwargs.pop('obj_typ', None)
    if not obj_typ: raise TypeError('Required argument obj_typ missing')
    query = {"$and" : [{"objects.0.type":obj_typ}]}

    if obj_typ in ['ipv4-add4','url']:
        obj_val = kwargs.pop('obj_val', None)
        if not obj_val: raise TypeError('Required argument obj_val missing')
        query["$and"].append({"objects.0.type":obj_typ})
    else: return None    
       
    
    utc = pytz.utc
    tzname = kwargs.pop('tzname', None)
    if not tzname: tzname = 'UTC'
    try: tz = pytz.timezone(tzname)
    except UnknownTimeZoneError: return 'Unknown Timezone'

    from_datetime = kwargs.pop('from_datetime', None)
    if from_datetime:
        try: from_datetime = parse_time(from_datetime)
        except ValueError: return 'Unknown fromtime'
        from_datetime = tz.localize(from_datetime).astimezone(utc)
        query["$and"].append({"x_first_observed": {"$gte": from_datetime}})

    to_datetime = kwargs.pop('to_datetime', None)
    if not to_datetime: to_datetime = utc.localize(datetime.utcnow())
    else:
        try: to_datetime = parse_time(to_datetime)
        except: return 'Unknown totime'
        to_datetime = tz.localize(to_datetime).astimezone(utc)
        try: query["$and"][1]["x_first_observed"]["$lte"] = to_datetime
        except KeyError: query["$and"].append({"x_first_observed": {"$lte": to_datetime}})

    number_observed = ancoll.find(query, {"_id":1},
        limit = 100000).count(with_limit_and_skip=True)
    if number_observed == 0: return None
    first_observed = ancoll.find_one(filter = query, sort=[("x_first_observed",
                    pymongo.ASCENDING)])["first_observed"]
    last_observed = ancoll.find_one(filter = query, sort=[("x_first_observed",
                    pymongo.DESCENDING)])["last_observed"]

    objects = {"0":{"type": obj_typ, "value" : obj_val}}
    obj = stix2.ObservedData(first_observed = first_observed,
        last_observed = last_observed, number_observed = number_observed,
        created_by_ref = _REPORT_ORGID, objects = objects)

    result_bundle = stix2.Bundle([obj])
    return json.loads(result_bundle.serialize())

cparser = reqparse.RequestParser()
cparser.add_argument('ipv4-addr')
cparser.add_argument('url')
cparser.add_argument('from')
cparser.add_argument('to')
cparser.add_argument('timezone')

class Count(Resource):

    @jwt_required
    def post(self):
        example = { "url" : "http://165.227.0.144:80/bins/rift.x86", "from" : "2018/4/1 00:00", "to" : "2020/4/2 00:00", "timezone" : "US/Pacific" }
        req = cparser.parse_args()
        valid_obj_typ = ['ipv4-addr', 'url']
        req_keys = req.keys()

        count = 0
        for ot in valid_obj_typ:
            ov = req[ot]
            if ov:
                obj_typ = ot
                obj_val = ov 
                count += 1        
        if count > 1: return ({'message' : 'Input one attribute object at a time', 'example':example}, 400)
            
        ip = req['ipv4-addr']
        url = req['url']
        from_datetime = req['from']
        to_datetime = req['to']
        tzname = req['timezone']
        
        if ip: r = get_count(obj_typ = 'ipv4-addr', obj_val = ip, from_datetime = from_datetime, to_datetime = to_datetime, tzname = tzname)
        elif url: r = get_count(obj_typ = 'url', obj_val = url, from_datetime = from_datetime, to_datetime = to_datetime, tzname = tzname)
        else: return ({'message': 'Input valid attribute object, check spelling', 'example':example}, 400) 
        if not r: r = {'message': obj_typ + ' object not found: ' + obj_val}

        return (r, 200)
