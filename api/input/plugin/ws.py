from lomond import WebSocket
from lomond.persist import persist
import json, logging, pdb

if __name__ == "__main__": from plugin_comm import *
else: from .plugin_comm import *

class WsInp(CybInp):
    def __init__(self, api_url, api_token, **kwargs):
        self.url = kwargs.pop('url')
        self.ws = WebSocket(self.url)
        super(WsInp, self).__init__(api_url, api_token, **kwargs)
        
    def __str__(self):
        return('Websocket input, orgid = {}, typtag = {},'\
               ' timezone = {}, url = {}'.format(self.orgid,
               self.typtag, self.timezone, self.url))

    def run(self):
        for event in persist(self.ws):
            if event.name == 'text':
                r = self.post_event(event.json)
                if not r.ok: logging.exception(str(r.status_code) + ' ' + r.reason)
            else:
                logging.info(event.name + ' ' + str(self))

def ws_proc(config):
    n = 0
    while True:
        try:
            wsi_lst = []
            api_url = config['api_srv']['url']
            api_token = config['api_srv']['token']
            for inp in config['input']:
                if inp['type'] == 'websocket-client':
                    wsi = WsInp(api_url, api_token, **inp)
                    wsi_lst.append(wsi)

            for wsi in wsi_lst:
                wsi.run()
                
        except Exception:
            logging.error("plugin.ws.ws_proc -- ", exc_info=True)
            exponential_backoff(n)
            
        n += 1

if __name__ == "__main__":
    with open("../../config.json") as f: config = json.load(f)
    input_config = config.pop("input", None)
    if not input_config: logging.error("plugin.ws: No input configuration found")

    ws_proc(input_config)
