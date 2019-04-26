import logging
import time
import requests
import urllib.parse
import threading
from threading import Thread
from multiprocessing import Process

# Configure Logging
logger = logging.getLogger('coll')
hdlr = logging.FileHandler('../input.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr) 
logger.setLevel(logging.INFO)

token = '0'
class get_token(threading.Thread):
    def __init__(self, api_srv):
        threading.Thread.__init__(self)
        self.api_srv = api_srv
        self.auth_url = api_srv + '/login'
        self.refresh_url = api_srv + '/token/refresh'
        self.refresh_token = False

    def __str__(self):
        return('Get Token, api server = {}, auth url = {}'.format(
            self.api_srv, self.auth_url))    
        
    def run(self):
        global token
        data = {"username":"admin","password":"admin"}
        while True:
            if not self.refresh_token:
                try:
                    r = requests.post(self.auth_url, json=data)
                    token = r.json()['access_token']
                    self.refresh_token = r.json()['refresh_token']
                except:
                    logger.exception("message")
            else:
                try:
                    headers={'Authorization': 'Bearer ' + self.refresh_token}
                    ret = requests.post(self.refresh_url, headers=headers)
                    token = ret.json()['access_token']
                except Exception as e:
                    logger.exception("message")                    
            time.sleep(800)

api_srv = "http://localhost:5000"
get_token_thread = get_token(api_srv)
get_token_thread.start()

class CybInp():
    def __init__(self, *args, **kwargs):
        self.api_srv = kwargs.pop('api_srv')
        self.post_url = api_srv + '/api/v1.0/event'

    def __str__(self):
        return('Cybexp Input, api server = {}, post url = {}'.format(
            self.api_srv, self.post_url))
               
    def post_event(self, event):
        global token
        data = json.dumps(event).encode()
        files = {'file':data}
        headers={'Authorization': 'Bearer '+ token}
        r = requests.post(self.post_url, files=files, headers=headers,
                          data = {'orgid': self.orgid,
                                  'typtag': self.typtag,
                                  'timezone': self.timezone})
        return r

# ====================================================
# ============= Websocket Input Plugin ===============
# ====================================================
import json, requests
from lomond import WebSocket
from lomond.persist import persist

class WsInp(CybInp):
    def __init__(self, *args, **kwargs):
        self.orgid = kwargs.pop('orgid')
        self.typtag = kwargs.pop('typtag')
        self.timezone = kwargs.pop('timezone')
        self.uri = kwargs.pop('uri')
        self.ws = WebSocket(self.uri)
        super(WsInp, self).__init__(*args, **kwargs)
        
    def __str__(self):
        return('Websocket input, orgid = {}, typtag = {},'\
               ' timezone = {}, uri = {}'.format(self.orgid,
               self.typtag, self.timezone, self.uri))

    def run(self):
        for event in persist(self.ws):
            if event.name == 'text':
                r = self.post_event(event.json)
                if not r.ok:
                    logger.exception(str(r.status_code) + ' ' + r.reason)
            else:
                logger.info(event.name + ' ' + str(self))

# Get list of inputs
with open('../config.json') as json_conf:
    conf = json.load(json_conf)

def ws_proc():
    wsi_lst = []
    for i in conf['input']:
        if i['type'] == 'websocket-client':
            wsi = WsInp(api_srv = api_srv,
                        orgid = i['orgid'],
                        typtag = i['typtag'],
                        timezone = i['timezone'],
                        uri = i['uri'])
            wsi_lst.append(wsi)

    for wsi in wsi_lst:
        wsi.run()



# ====================================================
# ================ API Input Plugin ==================
# ====================================================

# MISP Input API
def api_proc():
    url = urllib.parse.urljoin("https://ti-dev.soc.unr.edu", "/events/restSearch")
    key = "eqyU15K4MByA9t89lkXlbrG559gYC5LkVnQcSXrS"
    data = {
        "returnFormat": "json",
        "org": "CIRCL",
        "withAttachments": "false"
    }

    output = requests.post(url, headers={'Authorization': key}, json=data)
    out_text = output.text
    



# ====================================================
# ================ Start All Threads =================
# ====================================================

ws_p = Thread(target=ws_proc)
api_p = Thread(target=api_proc)

ws_p.start()
api_p.start()




