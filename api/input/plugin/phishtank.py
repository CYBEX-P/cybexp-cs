#!/usr/bin/env python3

import bz2, gzip

if __name__ == "__main__":
    from common import *
else:
    from .common import *

URL = "http://data.phishtank.com/data/"
COMPRESS_ALGO = ".bz2"  # need '.' for string fmt

decompress_algos = {".bz2": bz2.decompress, ".gz": gzip.decompress}

logging.basicConfig(level=logging.INFO)


class PhishtankSource(CybexSource):
    def fetch(self):
        logging.info(f"Retrieving events from Phishtank at {URL}")
        response = requests.get(
            f"{URL}/{self.phishtank_api_key}/online-valid.json{COMPRESS_ALGO}"
        )

        if COMPRESS_ALGO:
            logging.info(f"Decompressing API response from Phishtank with {COMPRESS_ALGO}")
            text = decompress_algos[COMPRESS_ALGO](response.content)
        else:
            text = response.text

        events = json.loads(text)
        logging.info(f"Retrieved {len(events)} records from PhishTank.")
        self.post_event_to_cybex_api(events)


def phishtank_fetch():
    config_file = get_config_file()
    api_config = config_file["api_srv"]
    phishtank_config = config_for_source_type(config_file, "phishtank")

    phishtank_source = PhishtankSource(api_config, phishtank_config)

    CybexSourceFetcher(phishtank_source, max_daily_fetches=2).run()


if __name__ == "__main__":
    phishtank_fetch()
