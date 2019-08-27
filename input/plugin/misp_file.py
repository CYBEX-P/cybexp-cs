#!/usr/bin/env python3
from .common import *


class MISPFileSource(CybexSource):
    def __init__(self, api_config, input_config, filename):
        self.filename = filename
        super().__init__(api_config, input_config)

    def __str__(self):
        return "MISP File input, orgid = {}, typtag = {}, timezone = {}, url = {}".format(
            self.orgid, self.typtag, self.timezone, self.url
        )

    def fetch_and_post(self):
        f = open(self.filename, "r")
        j = json.load(f)
        for event in j["response"]:
            rr = self.post_event_to_cybex_api(event)
            [
                logging.exception(str(r.status_code) + " " + r.reason)
                for r in rr
                if not r.ok
            ]
        f.close()
        os.rename(self.filename, self.filename + ".bak")
