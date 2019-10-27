## api.views.related

from collections import defaultdict
from flask_restful import reqparse

from tahoe import Attribute, parse

if __name__ in ['__main__', 'related']: from views_comm import *
else: from .views_comm import * 


class Count_B(AttReport):
    def getorpost(self):
        if 400 <= self.status <= 599:
            return {'error' : self.error}, self.status
        return self.get_count(), self.status

class Count(Count_B):
    def __init__(self):
        super().__init__(sub_type='count', report_id=20001, uuid='report--80e75238-01b6-4961-a7b9-76eba4a4573b')

    def get_count(self):
        c = self.att.count(start=self.start, end=self.end)
        return self.return_format(c)

class CountMalicious(Count_B):
    def __init__(self):
        super().__init__(sub_type='count_malicious', report_id=20002, uuid='report--5104ab12-5604-44b4-9b12-51882888a4f1')

    def get_count(self):
        c = self.att.count(start=self.start, end=self.end, malicious=True)
        return self.return_format(c)

class CountByEventAtt(Count_B):
    def __init__(self):
        self.get_level_page()
        super().__init__(sub_type='count_by_event_type_by_att_type', report_id=20004, uuid='report--087f1723-650a-41cc-99ff-f2c37e79d826')
        
    def get_count(self):
        data, curpg, nxtpg = self.att.countbyeventatt(start=self.start, end=self.end, limit=50, page=self.page)       
        return self.return_format_paginated(data, curpg, nxtpg)
    
class CountByOrgSummary(Count_B):
    def __init__(self):
        super().__init__(sub_type='count_by_org', report_id=20005, uuid='report--ab89901e-b1b6-4401-8c71-e5a7e946bfd2')

    def get_count(self):
        c = self.att.countbyorgsummary(key='org_name', start=self.start, end=self.end, malicious=False)
        return self.return_format(c)

class CountMaliciuosByOrgSummary(Count_B):
    def __init__(self):
        super().__init__(sub_type='count_malicious_by_org', report_id=20006, uuid='report--5c03e308-894c-4f23-8acf-c2609417d132')

    def get_count(self):
        c = self.att.countbyorgsummary(key='org_name', start=self.start, end=self.end, malicious=True)
        return self.return_format(c)

class CountByOrgCategorySummary(Count_B):
    def __init__(self):
        super().__init__(sub_type='count_by_org_category', report_id=20007, uuid='report--ed9d2ac8-729e-4c90-b814-cc9fb45c0a1e')

    def get_count(self):
        c = self.att.countbyorgsummary(key='org_category', start=self.start, end=self.end, malicious=False)
        return self.return_format(c)

class CountMaliciousByOrgCategorySummary(Count_B):
    def __init__(self):
        super().__init__(sub_type='count_by_org_category', report_id=20008, uuid='report--75b36f9e-287e-475a-b2e2-bac67145759d')

    def get_count(self):
        c = self.att.countbyorgsummary(key='org_category', start=self.start, end=self.end, malicious=True)
        return self.return_format(c)

        
        
    
