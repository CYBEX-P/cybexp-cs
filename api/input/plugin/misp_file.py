if __name__ == "__main__": from plugin_comm import *
else: from .plugin_comm import *

import os

class MispFileInp(CybInp):
    def __init__(self, api_url, api_token, filename, **kwargs):
        self.filename = filename
        super().__init__(api_url, api_token, **kwargs)
        
    def __str__(self):
        return('MISP File input, orgid = {}, typtag = {}, timezone = {}, url = {}'.format(
                self.orgid, self.typtag, self.timezone, self.url))

    def run(self):
        f = open(self.filename, "r")
        j = json.load(f)
        for event in j['response']:
            rr = self.post_event(event)
            [logging.exception(str(r.status_code) + ' ' + r.reason) for r in rr if not r.ok]
        f.close()
        os.rename(self.filename, self.filename+'.bak')


def misp_file_proc(config):
    n_failed_queries = 0    
    try:
        file_lst = []
        api_url = config['api_srv']['url']
        api_token = config['api_srv']['token']
        misp_file_config = config['input']['misp_file']
        loc = misp_file_config['directory']
        for filename in os.listdir(loc):
            if filename[-4:] == 'json':
                misp_filei = MispFileInp(api_url, api_token, os.path.join(loc,filename),**misp_file_config)
                file_lst.append(misp_filei)
                

        for misp_filei in file_lst:
            misp_filei.run()
            logging.info("cybexp.api.input.file.file_proc: This loop does not need threads")
            
        n_failed_queries = 0
        
    except Exception:
        logging.error("plugin.file.file_proc -- ", exc_info=True)
        exponential_backoff(n_failed_queries)
        n_failed_queries += 1

if __name__ == "__main__":
    with open("../../input_config.json") as f: input_config = json.load(f)
    if not input_config: logging.error("plugin.ws: No input configuration found")

    misp_file_proc(input_config)
