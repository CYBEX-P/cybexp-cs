import requests

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

