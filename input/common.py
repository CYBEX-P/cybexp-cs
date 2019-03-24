import logging
import threading
import time
import requests
import pdb

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

class CybInp():
    def __init__(self, api_srv):
        self.api_srv = api_srv
        self.post_url = api_srv + '/api/v1.0/event'

    def __str__(self):
        return('Cybexp Input, api server = {}, post url = {}'.format(
            self.api_srv, self.post_url))
               
    def post_event(self, event):
        global token
        data = json.dumps(event).encode()
        files = {'file':data}
        token = self.token
        headers={'Authorization': token}
        r = requests.post(url, files=files, headers=headers,
                          data = {'orgid': self.orgid,
                                  'typtag': self.typtag,
                                  'timezone': self.timezone})

api_srv = "http://localhost:5000"
get_token_thread = get_token(api_srv)
get_token_thread.start()
