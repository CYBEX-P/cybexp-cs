import logging
if __name__ == "__main__":
    from plugin_comm import *
    logging.basicConfig(filename = '../input.log', level=logging.DEBUG,
                    format='%(asctime)s %(message)s')
else:
    from .plugin_comm import *

from queue import Queue
from pymisp import PyMISP

class MispInp(CybInp):
    def __init__(self, *args, **kwargs):
        self.url = kwargs.pop('url')
        self.key = kwargs.pop('key')
        self.org = kwargs.pop('org')
        self.data = {
            "returnFormat": "json",
            "org" : self.org,
            "withAttachments": "false"
        }
        super(MispInp, self).__init__(*args, **kwargs)
        
    def __str__(self):
        return('MISP input, orgid = {}, typtag = {},'\
               ' timezone = {}, url = {}'.format(self.orgid,
               self.typtag, self.timezone, self.url))

    def run(self):
        misp_url = self.url
        misp_key = self.key
        misp_verifycert = True
        relative_path = 'events/restSearch'
        relative_path += '?last=1h'
        body = {
            
            "withAttachments": "false",
            "org" : self.org,
            "returnFormat": "json"
        }

        misp = PyMISP(misp_url, misp_key, misp_verifycert)
        r = misp.direct_call(relative_path, body)
        self.post_event(r['response'])

        
class MispInst(threading.Thread):
    def __init__(self, inp, all_org):
        self.inp = inp
        self.all_org = all_org
        threading.Thread.__init__(self)

    def run(self):        
        q = Queue()
        for org in self.all_org:
            q.put(org)

        inp = self.inp
        while not q.empty():
            org = q.get()

            inp['org'] = org
            misp_inp = MispInp(**inp)
            misp_inp.run()

            q.task_done()
            q.put(org)

            if org == "ESET":
                time.sleep("86400")
            



