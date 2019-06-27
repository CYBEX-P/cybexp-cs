# Imports
import requests, json, time, urllib, threading, logging

# Builtin variables
import builtins
builtins._TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzIiwianRpIjoiZWFhNDUzOWEtZjE5Yy00OWFiLThjNjktZTc4MDJiYmY5MmVhIiwiaWRlbnRpdHkiOiJhZG1pbiIsImZyZXNoIjpmYWxzZSwiaWF0IjoxNTU3MzYzNjI2LCJuYmYiOjE1NTczNjM2MjZ9.PcKIqxjlPGZQGeCyOakjYeKPPaVQvPhFSbrwJzeDTWc"

# Classes
class CybInp():
    def __init__(self, *args, **kwargs):
        self.api_srv = _CONF['api_srv']
        self.post_url = self.api_srv + '/api/v1.0/event'

        self.orgid = kwargs.pop('orgid')
        self.typtag = kwargs.pop('typtag')
        self.timezone = kwargs.pop('timezone', 'UTC')

    def __str__(self):
        return('Cybexp Input, api server = {}, post url = {}'.format(
            self.api_srv, self.post_url))
               
    def post_event(self, _event):
        event = _event
        if type(event) != list: event = [event]
        for e in event: 
            if type(e) != str: e = json.dumps(e)
            data = e.encode()
            files = {'file' : data}
            headers={'Authorization': 'Bearer '+ _TOKEN}

        
            r = requests.post(self.post_url, files=files, headers=headers,
                              data = {'orgid': self.orgid,
                                      'typtag': self.typtag,
                                      'timezone': self.timezone})
            return r


    
