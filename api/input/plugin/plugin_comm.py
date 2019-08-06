# Imports
import requests, json, time, urllib, threading, logging, random, copy, os, pdb

def exponential_backoff(n):
    s = max(3600, (2 ** n) + (random.randint(0, 1000) / 1000))
    time.sleep(s)

# Classes
class CybInp():
    def __init__(self, url, token, **kwargs):
        self.post_url = url + '/api/v1.0/event'
        self.token = token
        self.orgid = kwargs.pop('orgid')
        self.typtag = kwargs.pop('typtag')
        self.timezone = kwargs.pop('timezone', 'UTC')

    def __str__(self):
        return('Cybexp Input, api server = {}, post url = {}'.format(
            self.api_srv, self.post_url))
               
    def post_event(self, _event):
        event = _event
        if type(event) != list: event = [event]
        rr = []

        for e in event: 
            if isinstance(e, dict): e = json.dumps(e)
            data = e.encode()
            files = {'file' : data}
            headers={'Authorization': 'Bearer '+ self.token}

            try:
                with requests.post(self.post_url, files=files, headers=headers,
                                   data = {'orgid': self.orgid,
                                           'typtag': self.typtag,
                                           'timezone': self.timezone}) as r:
                    rr.append(r)

            except requests.exceptions.ConnectionError:
                logging.error("api.input.plugin.plugin_comm.CybInp -- \n" + e , exc_info=True)
            
        return rr


    
