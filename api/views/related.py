if __name__ == "__main__": from views_comm import *
else: from .views_comm import * 
from tahoe import Attribute, parse
from flask_restful import Resource, reqparse
import pdb

rparser = reqparse.RequestParser()
for att_type in _VALID_ATT: rparser.add_argument(att_type)
rparser.add_argument('level', type=int)

class Related(Resource):
    def __init__(self):
        req = rparser.parse_args()
        req = {k:v for k,v in req.items() if v is not None}
        self.lvl = req.pop('level', 1)
        self.att_type, self.data = list(req.items())[0]

    @jwt_required
    def post(self):
        r = self.get_related()
        return (r, 200)

    def get_related(self, itype=None):
            att = Attribute(self.att_type, self.data)
            if itype: r = att.related(self.lvl, itype)
            else: r = att.related(self.lvl)
            e = []
            for i in r: e.append(i)
            return e

class RelatedAttribute(Related):
    def get_related(self):
        return super().get_related("attribute")

class RelatedAttributeSummary(RelatedAttribute):
    def get_related(self):
        att = Attribute(self.att_type, self.data)

        r = att.related(self.lvl, "attribute", {"uuid":1, "sub_type":1,"data":1})

        e = {}
        for i in r:
            t, v = i["sub_type"], i["data"]
            if t not in e: e[t] = [v]
            else: e[t].append(v)
        return e

class RelatedEventSummary(Related):
    def get_related(self):
        att = Attribute(self.att_type, self.data)
        r = att.related(self.lvl, "event", {"uuid":1, "itype":1,"sub_type":1,"data":1})
        e = {}

        res = {}
        for i in r:
            e = parse(i)
            f = e.features()
            for k, v in f.items():
                if self.data in v:
                    if e.sub_type not in res:
                        res[e.sub_type] = {}
                    if k not in res[e.sub_type]:
                        res[e.sub_type][k] = 1
                    else:
                        res[e.sub_type][k] += 1
        return res
            
        

