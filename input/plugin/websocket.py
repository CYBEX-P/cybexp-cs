#!/usr/bin/env python3
from .common import *

from lomond import WebSocket
from lomond.persist import persist


class WebsocketSource(CybexSource):
    def __init__(self, api_config, input_config):
        super().__init__(api_config, input_config)
        self.ws = WebSocket(self.url)

    def __str__(self):
        return "Websocket input, orgid = {}, typtag = {}, timezone = {}, url = {}".format(
            self.orgid, self.typtag, self.timezone, self.url
        )

    def fetch_and_post(self):
        for event in persist(self.ws):
            if event.name == "text":
                rr = self.post_event_to_cybex_api(event.json)
                [
                    logging.exception(str(r.status_code) + " " + r.reason)
                    for r in rr
                    if not r.ok
                ]
            else:
                logging.info(event.name + " " + str(self))
