if __name__ == "__main__": from views_comm import *
else: from .views_comm import * 

from flask_restful import Resource, reqparse, inputs
from tahoe.report import Report
import pdb

p = reqparse.RequestParser()
p.add_argument('count', type=inputs.boolean)
p.add_argument('att_type', type=str)

class AttributeSummary(Resource):
    @jwt_required
    def get(self, **kwargs):
        req = p.parse_args()
        req.update(kwargs)

        att_type = req.pop("att_type")
        count = req.pop("count")
        if count is None: count = True

        rp = Report()

        return(rp.attribute_types(count))
    


class AttributeValueSummary(CybResource):
    @jwt_required
    def get(self, *args, **kwargs):
        req = p.parse_args()
        req.update(kwargs)

        att_type = req.pop("att_type")
        count = req.pop("count")
        if count is None: count = False
        
        rp = Report()
        if not att_type in _VALID_ATT:
            return ({"text": "Invalid attribute type : " + att_type}, 404)

        return rp.attribute_values(att_type, count)



    def post(self, **kwargs):
        req = p.parse_args()
        req.update(kwargs)

        att_type = req.pop("att_type")
        count = req.pop("count")
        if count is None: count = False
        
        rp = Report()
        if not att_type in _VALID_ATT:
            return ({"text": "Invalid attribute type : " + att_type}, 404)
        
        self.get_dtrange()
        
        if not self.dtreq: return rp.attribute_values(att_type, count)
        else: return rp.attribute_values(att_type, count, self.start, self.end)

class EventSummary(Resource):
    @jwt_required
    def get(self):
        rp = Report()
        return (rp.event_types(), 200)


        
        
    
