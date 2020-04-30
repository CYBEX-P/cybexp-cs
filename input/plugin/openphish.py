#!/usr/bin/env python3

from .common import *
import requests

FEED_URL = "https://openphish.com/feed.txt"

class OpenphishSource(CybexSource):
    def fetch_and_post(self):

        logging.info(f"Retrieving events from OpenPhish at {FEED_URL}")
        response = requests.get(FEED_URL)

        if response.ok:

            text = response.text
            count = text.count('\n')
            logging.info(f"Retrieved {count} records from OpenPhish.")
            self.post_event_to_cybex_api(text)

        else:
            logging.error(
                "api.input.openpishSource.fetch -- \n\t" + response.reason
            )
