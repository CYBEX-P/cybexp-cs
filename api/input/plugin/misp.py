if __name__ == "__main__": from plugin_comm import *
else: from .plugin_comm import *

from pymisp import PyMISP

class MispInp(CybInp):
    def __init__(self, api_url, api_token, **kwargs):
        self.misp_url, self.misp_key, self.misp_org, self.misp_verifycert = kwargs.pop('url'), kwargs.pop('key'), kwargs.pop('org'), kwargs.pop('verifycert', True)
        super().__init__(api_url, api_token, **kwargs)
        
    def __str__(self):
        return('MISP input, orgid = {}, typtag = {}, timezone = {}, url = {}, misp org id = {}'.format(
                self.orgid, self.typtag, self.timezone, self.url, self.org))

    def run(self):
        misp = PyMISP(self.misp_url, self.misp_key, self.misp_verifycert)
        relative_path = 'events/restSearch'
        body = {"org" : self.misp_org, "withAttachments": "false", "returnFormat": "json"}
        r = misp.direct_call(relative_path, body)

        if 'errors' in r.keys(): logging.error("api.input.misp.MispInp.run -- \n" + json.dumps(r, indent=4))
        elif 'response' in r.keys(): self.post_event(r['response'])
        else: logging.error("api.input.misp.MispInp.run -- \n" + json.dumps(r, indent=4))

class MispInst(threading.Thread):
    def __init__(self, api_url, api_key, **inp):
        self.inp, self.all_org, self.api_url, self.api_key = inp, inp['org'], api_url, api_key
        if not isinstance(self.all_org, list): self.all_org = [self.all_org]
        super().__init__()

    def run(self):
        n = 0
        while True:
            try:
                for org in self.all_org:
                    inp = copy.deepcopy(self.inp)
                    inp['org'] = org
                    misp_inp = MispInp(self.api_url, self.api_key, **inp)
                    misp_inp.run()
                n = 0
                time.sleep(43200)

            except:
                logging.error("api.input.misp.MispInst.run -- ", exc_info=True)
                exponential_backoff(n)
                n += 1

def misp_proc(config):
    try:
        misp_list = []
        api_url = config['api_srv']['url']
        api_token = config['api_srv']['token']
        misp_config = config['input']['misp-api']
        MispInst(api_url, api_token, **misp_config).run()
    except Exception: logging.error("api.input.misp.misp_proc -- bad input config -- " + str(config), exc_info=True)
        

if __name__ == "__main__":
    with open("../../input_config.json") as f: input_config = json.load(f)
    if not input_config: logging.error("api.input.plugin.misp -- No input configuration found")

    misp_proc(input_config)


