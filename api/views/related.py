## api.views.related

from collections import defaultdict
from flask_restful import Resource, reqparse

from tahoe import Attribute, parse, NoBackend, Object

if __name__ in ['__main__', 'related']: from views_comm import *
else: from .views_comm import * 


rprsr = attprsr
rprsr.add_argument('level', type=int)
rprsr.add_argument('page', type=int)

_MAX_EVENT = 50

class Related_B(CybResource):
    def __init__(self):
        self.status = 206
        
        req = rprsr.parse_args()
        req = {k:v for k,v in req.items() if v is not None}

        self.lvl = req.pop('level', 1)
        self.page = req.pop('page', 1)
        
        if not req.items():
            self.error = 'Invalid or missing att_type'
            self.status = 400
            return

        att_type, data = list(req.items())[0]
        self.att = Attribute(att_type, data)

        super().__init__()

    @jwt_required
    def get(self): return self.getorpost()

    @jwt_required
    def post(self): return self.getorpost()

    def getorpost(self):
        if 400 <= self.status <= 599:
            return {'error' : self.error}, self.status
        return self.get_related(), self.status

    def return_format(self, data, curpg, nxtpg, totpg):
        if not data: self.status = 205
        elif totpg == 1: self.status = 200
        return {
            'itype': 'report', 'sub_type' : self.sub_type,
            'orgid' : _REPORT_ORGID, 'timestamp':time.time(),
            'uuid' : self.uuid, 'report_id' : self.report_id,
            'next' : '/api/v1.0/related?' + self.att.sub_type +
            '=' + str(self.att.data) + '&' + 'page='+str(nxtpg),
            'current_page' : curpg, 'next_page' : nxtpg, 'total_page' : totpg,
            'data' : data,
        }

class Related(Related_B):
    def __init__(self):
        self.sub_type = 'related'
        self.report_id = 100001
        self.uuid = 'report--9601e721-3eef-4e03-928e-1c4520d50388'
        super().__init__()
        
    def get_related(self, itype=None):
        r, curpg, nxtpg, totpg = self.att.related(self.lvl, page=self.page)
        data = [i for i in r]
        return self.return_format(data, curpg, nxtpg, totpg)       

class RelatedAttribute(Related_B):
    def __init__(self):
        self.sub_type = 'related_attribute'
        self.report_id = 100002
        self.uuid = 'report--09bd95e3-7879-4148-b1d3-f91a0e63e5dd'
        super().__init__()
        
    def get_related(self):
        r, curpg, nxtpg, totpg = self.att.related(self.lvl, itype='attribute', page=self.page)
        data = [i for i in r]
        return self.return_format(data, curpg, nxtpg, totpg)

class RelatedAttributeSummary(Related_B):
    def __init__(self):
        self.sub_type = 'related_attribute_summary'
        self.report_id = 100003
        self.uuid = 'report--d68ed9c1-448c-4368-ba67-4f36c0e68337'
        super().__init__()
        
    def get_related(self):
        r, curpg, nxtpg, totpg = self.att.related(self.lvl, itype='attribute', limit=50, page=self.page)
        data = defaultdict(list)
        for i in r:
            data[i["sub_type"]].append(i["data"])
        return self.return_format(data, curpg, nxtpg, totpg)

class RelatedEventSummary(Related_B):
    def __init__(self):
        self.sub_type = 'related_event_summary'
        self.report_id = 100004
        self.uuid = 'report--087f1723-650a-41cc-99ff-f2c37e79d826'
        super().__init__()
        
    def get_related(self):
        if self.dtreq:
            data, curpg, nxtpg, totpg = self.att.relatedeventsummary(start=self.start, end=self.end, limit=50, page=self.page)
        else:
            data, curpg, nxtpg, totpg = self.att.relatedeventsummary(limit=100, page=self.page)                      
        return self.return_format(data, curpg, nxtpg, totpg)

class RelatedAttributeSummaryByEvent(Related_B):
    def __init__(self):
        self.sub_type = 'related_attribute_summary_by_event'
        self.report_id = 100005
        self.uuid = 'report--630a9a2f-600c-4d22-bc64-d7220191fbca'
        super().__init__()
        
    def get_related(self):
        data, curpg, nxtpg, totpg = self.att.relatedsummarybyevent(self.lvl, limit=50, page=self.page)                      
        return self.return_format(data, curpg, nxtpg, totpg)







