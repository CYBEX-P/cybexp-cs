if __name__ == "__main__":
    from views_comm import *
else:
    from .views_comm import * # .views=views.py, views=this folder

# Load Analytics Database
ancoll = coll_or_fs('analytics')

def get_count(obj_typ, obj_val, **kwargs):
    query = { "$and" : [ {"objects.0.type" : obj_typ} ]}
    
    # Take care of special structures
    if obj_typ == 'file': query["$and"].append({"objects.0.hashes.SHA-256" : obj_val} )
    else: query["$and"].append({"objects.0.value" : obj_val} )
    
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
    if to_datetime:
        try: to_datetime = parse_time(to_datetime)
        except: return 'Unknown totime'
        to_datetime = tz.localize(to_datetime).astimezone(utc)
        try: query["$and"][2]["x_first_observed"]["$lte"] = to_datetime
        except IndexError: query["$and"].append({"x_first_observed": {"$lte": to_datetime}})

    number_observed = ancoll.find(query, {"_id":1},
        limit = _QLIM).count(with_limit_and_skip=True)
    
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
for va in _VALID_ATT: cparser.add_argument(va)
for fa in _FUTURE_ATT: cparser.add_argument(fa)
cparser.add_argument('from')
cparser.add_argument('to')
cparser.add_argument('timezone')

class Count(Report):
    def __init__(self):
        super().__init__({ "url" : "http://165.227.0.144:80/bins/rift.x86", "from" : "2018/4/1 00:00", "to" : "2020/4/2 00:00", "timezone" : "US/Pacific" })

    @jwt_required
    def post(self):
        if not self.valid_att(cparser): return (self.response, self.status_code)

        from_datetime = self.request['from']
        to_datetime = self.request['to']
        tzname = self.request['timezone']

        r = get_count(self.obj_typ, self.obj_val, from_datetime = from_datetime, to_datetime = to_datetime, tzname = tzname)
        
        if not r:  r = {'message': self.obj_typ + ' object not found: ' + self.obj_val}
        return (r, 200) 
