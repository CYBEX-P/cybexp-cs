#!/usr/bin/env python3
from .common import *

from pymisp import PyMISP


class MISPServerSource(CybexSource):
    def __init__(self, api_config, input_config, misp_org):
        super().__init__(api_config, input_config)
        self.misp_org = misp_org

    def fetch_and_post(self):
        misp = PyMISP(self.misp_url, self.misp_key, self.misp_verifycert)
        relative_path = "events/restSearch"
        body = {
            "org": self.misp_org,
            "withAttachments": "false",
            "returnFormat": "json",
        }
        r = misp.direct_call(relative_path, body)

        if "errors" in r.keys():
            logging.error(
                "api.input.misp.MISPServerSource.fetch -- \n" + json.dumps(r, indent=4)
            )
        elif "response" in r.keys():
            self.post_event_to_cybex_api(r["response"])
        else:
            logging.error(
                "api.input.misp.MISPServerSource.fetch -- \n" + json.dumps(r, indent=4)
            )
