if __name__ == "__main__":
    from plugin_comm import *   
    logging.basicConfig(filename = '../input.log', level=logging.DEBUG,
                    format='%(asctime)s %(message)s')

    import json
    with open('../../config.json') as json_conf:
        conf = json.load(json_conf)
    builtins._CONF = conf
else:
    from .plugin_comm import *

    
from lomond import WebSocket
from lomond.persist import persist

class WsInp(CybInp):
    def __init__(self, *args, **kwargs):
        self.url = kwargs.pop('url')
        self.ws = WebSocket(self.url)
        super(WsInp, self).__init__(*args, **kwargs)
        
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


def ws_proc():
    wsi_lst = []
    for inp in _CONF['input']:
        if inp['type'] == 'websocket-client':
            wsi = WsInp(**inp)
            wsi_lst.append(wsi)

    for wsi in wsi_lst:
        wsi.run()

