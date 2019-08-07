if __name__ == "__main__": from views_comm import *
else: from .views_comm import * 

from flask_restful import Resource, reqparse
from tahoe.report import Report
import pdb



class AttributeSummary(Resource):
    @jwt_required
    def get(self):
        rp = Report()
        return (rp.attribute_types(), 200)
    


class AttributeValueSummary(Resource):
    @jwt_required
    def get(self, *args, **kwargs):
        p = reqparse.RequestParser()
        p.add_argument('count', type=bool)
        p.add_argument('att_type', type=str)

        req = p.parse_args()
        req.update(kwargs)

        att_type = req.pop("att_type")
        count = req.pop("count")
        if count is None: count = False
        
        rp = Report()
        if not att_type in _VALID_ATT:
            return ({"text": "Invalid attribute type : " + att_type}, 404)

        return rp.attribute_values(att_type, count=count)

class EventSummary(Resource):
    @jwt_required
    def get(self):
        rp = Report()
        return (rp.event_types(), 200)


        
        
    
