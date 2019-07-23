if __name__ == "__main__": from views_comm import *
else: from .views_comm import * 
from tahoe import Attribute, parse
from flask_restful import Resource, reqparse
import pdb

parser = reqparse.RequestParser()
for att_type in _VALID_ATT: parser.add_argument(att_type)

class Count(Resource):
    def __init__(self):
        req = parser.parse_args()
        req = {k:v for k,v in req.items() if v is not None}
        self.att_type, self.value = list(req.items())[0]

    @jwt_required
    def post(self):
        r = self.get_count()
        return (r, 200)

    def get_count(self):
            att = Attribute(self.att_type, self.value)
            c = att.count()
            return {"count" : c, att.att_type : att.value}


        
        
    
