if __name__ == "__main__": from views_comm import *
else: from .views_comm import * 
from tahoe import Attribute, parse
from flask_restful import Resource, reqparse
import pdb

parser = reqparse.RequestParser()
for att_type in _VALID_ATT: parser.add_argument(att_type)

class Count(CybResource):
    def __init__(self):
        self.invalid = False
        
        req = parser.parse_args()
        req = {k:v for k,v in req.items() if v is not None}
        if req: self.att_type, self.data = list(req.items())[0]
        else: self.invalid = True
        
        super().__init__()

    @jwt_required
    def post(self):
        if self.invalid: return {'error':"Invalid attribute type"}, 400
        
        r = self.get_dtrange()
        if not r: return {"message" : self.error}, self.code
        
        att = Attribute(self.att_type, self.data)
        c = att.count(self.start, self.end)
        mc = att.count(self.start, self.end, malicious=True)
        return {"count" : c, "malicious":mc, att.sub_type : att.data}, 200

class CountByOrgSummary(Count):
    @jwt_required
    def post(self):
        if self.invalid: return {'error':"Invalid attribute type"}, 400
        
        r = self.get_dtrange()
        if not r: return {"message" : self.error}, self.code
        
        att = Attribute(self.att_type, self.data)
        rep = att.countbyorgsummary(start=self.start, end=self.end)
        return rep, 200

class CountByOrgCategorySummary(Count):
    @jwt_required
    def post(self):
        if self.invalid: return {'error':"Invalid attribute type"}, 400
        
        r = self.get_dtrange()
        if not r: return {"message" : self.error}, self.code
        
        att = Attribute(self.att_type, self.data)
        rep = att.countbyorgsummary('org_category', start=self.start, end=self.end)
        return rep, 200
        
        
    
