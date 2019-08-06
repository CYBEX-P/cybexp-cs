if __name__ == "__main__": from views_comm import *
else: from .views_comm import * 

from tahoe.report import Report
from tahoe import parse
from flask_restful import Resource, reqparse
import pdb

parser = reqparse.RequestParser()
parser.add_argument('page', type=int)
parser.add_argument('limit', type=int)

class EventFeatures(Resource):
    @jwt_required
    def get(self, *args, **kwargs):
        req = parser.parse_args()
        req = {k:v for k,v in req.items() if v is not None}

        page_no = req.pop('page',0)
        limit = min(req.pop('limit',100),1000)
        
        rp = Report()
        events = rp.events(limit, max(page_no-1,0))

        result = {}
        for e in events:
            e = parse(e)
            result[e.uuid] = e.feature()

        return (result, 200)
        
        


