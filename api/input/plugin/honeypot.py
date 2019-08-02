#!/usr/bin/env python3

if __name__ == "__main__": from common import *
else: from .common import *

from lomond import WebSocket
from lomond.persist import persist

class HoneypotSource(CybexSource):
    def __init__(self, api_config, input_config):
        super().__init__(api_config, input_config)
        self.ws = WebSocket(self.url)
        
    def __str__(self):
        return('Websocket input, orgid = {}, typtag = {}, timezone = {}, url = {}'.format(
                self.orgid, self.typtag, self.timezone, self.url))

    def fetch(self):
        for event in persist(self.ws):
            if event.name == 'text':
                rr = self.post_event_to_cybex_api(event.json)
                [logging.exception(str(r.status_code) + ' ' + r.reason) for r in rr if not r.ok]
            else:
                logging.info(event.name + ' ' + str(self))


def honeypot_fetch():
    config_file = get_config_file()
    api_config = config_file["api_srv"]
    honeypot_config = config_for_source_type(config_file, "websocket")

    honeypot_source = HoneypotSource(api_config, honeypot_config)

    CybexSourceFetcher(honeypot_source).run()


if __name__ == "__main__":
    honeypot_fetch()
