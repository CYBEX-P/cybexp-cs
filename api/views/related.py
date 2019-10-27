## api.views.related

from collections import defaultdict
from flask_restful import reqparse

from tahoe import Attribute, parse, NoBackend, Object

if __name__ in ['__main__', 'related']: from views_comm import *
else: from .views_comm import * 




_MAX_EVENT = 50

class Related_B(AttReport):
    def __init__(self, *args, **kwargs):       
        self.get_level_page()
        super().__init__(*args, **kwargs)

    def getorpost(self):
        if 400 <= self.status <= 599:
            return {'error' : self.error}, self.status
        return self.get_related(), self.status

class Related(Related_B):
    def __init__(self):
        super().__init__(sub_type='related', report_id=100001, uuid='report--9601e721-3eef-4e03-928e-1c4520d50388')
        
    def get_related(self, itype=None):
        r, curpg, nxtpg = self.att.related(self.lvl, start=self.start, end=self.end, page=self.page)
        data = [i for i in r]
        return self.return_format_paginated(data, curpg, nxtpg)       

class RelatedAttribute(Related_B):
    def __init__(self):
        super().__init__(sub_type='related_attribute', report_id=100002, uuid='report--09bd95e3-7879-4148-b1d3-f91a0e63e5dd')
        
    def get_related(self):
        r, curpg, nxtpg = self.att.related(self.lvl, itype='attribute', start=self.start, end=self.end, page=self.page)
        data = [i for i in r]
        return self.return_format_paginated(data, curpg, nxtpg)

class RelatedEvent(Related_B):
    def __init__(self):
        super().__init__(sub_type='related_event', report_id=100003, uuid='report--f47f89fa-832b-42b2-b1d4-6b2d125120e0')
        
    def get_related(self):
        print(self.start, self.end)
        r, curpg, nxtpg = self.att.related(self.lvl, itype='event', start=self.start, end=self.end, page=self.page)
        data = [i for i in r]
        return self.return_format_paginated(data, curpg, nxtpg)

class RelatedAttributeSummary(Related_B):
    def __init__(self):
        super().__init__(sub_type='related_attribute_summary', report_id=100004, uuid='report--d68ed9c1-448c-4368-ba67-4f36c0e68337')
        
    def get_related(self):
        r, curpg, nxtpg = self.att.related(self.lvl, itype='attribute', start=self.start, end=self.end, page=self.page)
        data = defaultdict(list)
        for i in r:
            data[i["sub_type"]].append(i["data"])
        return self.return_format_paginated(data, curpg, nxtpg)


class RelatedAttributeSummaryByEvent(Related_B):
    def __init__(self):
        super().__init__(sub_type='related_attribute_summary_by_event', report_id=100005, uuid='report--630a9a2f-600c-4d22-bc64-d7220191fbca')
        
    def get_related(self):
        data, curpg, nxtpg = self.att.relatedsummarybyevent(self.lvl, start=self.start, end=self.end, limit=50, page=self.page)                  
        return self.return_format_paginated(data, curpg, nxtpg)







