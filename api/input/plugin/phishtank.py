#!/usr/bin/env python3

import bz2, gzip, json, logging, requests, time

if __name__ == "__main__":
    from plugin_comm import *
else:
    from .plugin_comm import *

URL = "http://data.phishtank.com/data/"
COMPRESS_ALGO = ".bz2"  # need '.' for string fmt

decompress_algos = {".bz2": bz2.decompress, ".gz": gzip.decompress}


class PhishtankSource(CybInp):
    def __init__(self, api_url, api_token, **kwargs):
        self.phishtank_api_key = kwargs.pop("phishtank_api_key")
        super(PhishtankSource, self).__init__(api_url, api_token, **kwargs)

    def run(self):
        response = requests.get(
            f"{URL}/{self.phishtank_api_key}/online-valid.json{COMPRESS_ALGO}"
        )

        if COMPRESS_ALGO:
            text = decompress_algos[COMPRESS_ALGO](response.content)
        else:
            text = response.text

        events = json.loads(text)
        print(f"Retrieved {len(events)} records from PhishTank. Posting...")
        self.post_event(events)

        print("Done, sleeping.")
        time.sleep(10)


def phishtank_fetch(config):
    while True:
        api_url = config["api_srv"]["url"]
        api_token = config["api_srv"]["token"]
        phishtank_api_config = config["input"]["phishtank"]
        PhishtankSource(api_url, api_token, **phishtank_api_config).run()

        logging.error("plugin.phishtank.phishtan-proc -- ", exc_info=True)


if __name__ == "__main__":
    print("Querying Phishtank API from a CLI.")
    with open("../../input_config.json") as f:
        input_config = json.load(f)

    phishtank_fetch(input_config)
