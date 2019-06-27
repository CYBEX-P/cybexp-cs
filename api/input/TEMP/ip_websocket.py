import json, requests
from lomond import WebSocket
from lomond.persist import persist
from common import CybInp


class WsInp(CybInp):
    API_SRV = 'http://localhost:5000/api/v1.0/event'
    def __init__(self, orgid, typtag, timezone, uri=''):
        self.orgid = orgid
        self.typtag = typtag
        self.timezone = timezone
        self.uri = uri
        self.ws = WebSocket(self.uri)
        
    def __str__(self):
        return('Websocket input, orgid = {}, typtag = {},'\
               ' timezone = {}, uri = {}'.format(self.orgid,
               self.typtag, self.timezone, self.uri))

    def run(self):
        for event in persist(self.ws):
            if event.name == 'text':
                self.post_event(event.json)
            else:
                logger.info(event.name + ' ' + str(self))

# Get list of inputs
with open('../config.json') as json_conf:
    conf = json.load(json_conf)

wsi_lst = []
for i in conf['input']:
    if i['type'] == 'websocket-client':
        wsi = WsInp(orgid = i['orgid'],
                      typtag = i['typtag'],
                      timezone = i['timezone'],
                      uri = i['uri'])
        wsi_lst.append(wsi)


for wsi in wsi_lst:
    wsi.run()
