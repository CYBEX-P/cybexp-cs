#!/usr/bin/env python3

if __name__ == "__main__": from common import *
else: from .common import *

from pymisp import PyMISP

class MISPServerSource(CybexSource):
    def __init__(self, api_config, input_config, misp_org):
        super().__init__(api_config, input_config)
        self.misp_org = misp_org


    def fetch(self):
        misp = PyMISP(self.misp_url, self.misp_key, self.misp_verifycert)
        relative_path = 'events/restSearch'
        body = {"org" : self.misp_org, "withAttachments": "false", "returnFormat": "json"}
        r = misp.direct_call(relative_path, body)

        if 'errors' in r.keys(): logging.error("api.input.misp.MISPServerSource.fetch -- \n" + json.dumps(r, indent=4))
        elif 'response' in r.keys(): self.post_event_to_cybex_api(r['response'])
        else: logging.error("api.input.misp.MISPServerSource.fetch -- \n" + json.dumps(r, indent=4))


def misp_server_fetch():
    config_file = get_config_file()
    api_config = config_file["api_srv"]
    misp_server_config = config_for_source_type(config_file, "misp_api")

    if not isinstance(misp_server_config["orgs"], list):
        misp_server_config["orgs"] = [ misp_server_config["orgs"] ]

    for org in misp_server_config["orgs"]:
        misp_server_source = MISPServerSource(api_config, misp_server_config, misp_org=org)
        CybexSourceFetcher(misp_server_source, seconds_between_fetches=43200).start()


if __name__ == "__main__":
    misp_server_fetch()

