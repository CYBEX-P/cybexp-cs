if __name__ == "__main__":
    from views_comm import *
else:
    from .views_comm import * # .views=views.py, views=this folder

# Load Analytics Database
ancoll = coll_or_fs('analytics')


cparser = reqparse.RequestParser()
for va in _VALID_ATT: cparser.add_argument(va)
for fa in _FUTURE_ATT: cparser.add_argument(fa)
cparser.add_argument('from')
cparser.add_argument('to')
cparser.add_argument('timezone')

class Count(Report):
    def __init__(self):
        super().__init__(example = { "url" : "http://165.227.0.144:80/bins/rift.x86", "from" : "2018/4/1 00:00", "to" : "2020/4/2 00:00", "timezone" : "US/Pacific" })

    def get_count(self):
        # Take care of special structures
        if self.obj_typ == 'file': self.query["$and"].append({"objects.0.hashes.SHA-256" : self.obj_val} )
        else: self.query["$and"].append({"objects.0.value" : self.obj_val} )
        
        number_observed = ancoll.find(self.query, {"_id":1},
            limit = _QLIM).count(with_limit_and_skip=True)
        
        if number_observed == 0: return None
        first_observed = ancoll.find_one(filter = self.query, sort=[("x_first_observed",
                        pymongo.ASCENDING)])["first_observed"]
        last_observed = ancoll.find_one(filter = self.query, sort=[("x_first_observed",
                        pymongo.DESCENDING)])["last_observed"]

        objects = {"0":{"type": self.obj_typ, "value" : self.obj_val}}
        obj = stix2.ObservedData(first_observed = first_observed,
            last_observed = last_observed, number_observed = number_observed,
            created_by_ref = _REPORT_ORGID, objects = objects)

        result_bundle = stix2.Bundle([obj])
        return json.loads(result_bundle.serialize())
        
    @jwt_required
    def post(self):
        if not self.valid_att(cparser): return (self.response, self.status_code)

        self.query = { "$and" : [ {"objects.0.type" : self.obj_typ} ]}
        
        self.from_datetime = self.request['from']
        self.to_datetime = self.request['to']
        self.tzname = self.request['timezone']

        if not self.qadd_dtrange(): return (self.response, self.status_code)
        
        r = self.get_count()
        
        if not r:  r = self.empty_stix2_bundle
        return (r, 200) 
