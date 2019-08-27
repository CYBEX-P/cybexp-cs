# Imports
import datetime, json, logging, random, requests, threading, time, uuid


class BadConfig(Exception):
    pass


def exponential_backoff(n):
    s = min(3600, (2 ** n) + (random.randint(0, 1000) / 1000))
    resume_time = (datetime.datetime.now() + datetime.timedelta(seconds=s)).strftime(
        "%I:%M:%S %p"
    )
    logging.error(f"Sleeping for {s} seconds, will resume around {resume_time}.")
    time.sleep(s)


class CybexSource:
    timezone = "UTC"

    def __init__(self, api_config, input_config):
        logging.info(
            f"Configuring {self.__class__.__name__} with "
            f"type = {input_config['type']} "
            f"orgid = {input_config['orgid']} "
            f"typtag = {input_config['typtag']} "
            f"timezone = {input_config['timezone']} "
        )

        # Should extract orgid, typtag, timezone from input_config.json
        for config_element, config_value in input_config.items():
            setattr(self, config_element, config_value)

        def validate_input_config():
            """ Validate configuration for this specific Cybex vuln. source. """
            if ("orgid", "typtag") - input_config.keys():
                raise BadConfig("Config needs an Org ID and a type tag.")

            try:
                uuid.UUID(self.orgid)
            except ValueError:
                raise BadConfig(f"Config needs a valid UUID, got {self.orgid}")

        validate_input_config()

        self.post_url = api_config["url"] + "/api/v1.0/raw"
        self.token = api_config["token"]

    def __str__(self):
        return "Cybexp Input, api server = {}, post url = {}".format(
            self.api_srv, self.post_url
        )

    def fetch_and_post(self):
        """ Fetch vulnerability data from this Cybex source. """
        raise NotImplementedError

    def post_event_to_cybex_api(self, events):
        """ Post an event from the Cybex source to the Cybex API. """
        if type(events) != list:
            events = [events]
        api_responses = []

        if events:
            logging.info(f"Posting {len(events)} events from {self.name} to Cybex API.")

        for event in events:
            if isinstance(event, dict):
                event = json.dumps(event)
            data = event.encode()
            files = {"file": data}
            headers = {"Authorization": "Bearer " + self.token}

            while True:
                n_failed_requests = 0
                try:
                    with requests.post(
                        self.post_url,
                        files=files,
                        headers=headers,
                        data={
                            "orgid": self.orgid,
                            "typtag": self.typtag,
                            "timezone": self.timezone,
                            "name": self.name,
                        },
                    ) as r:
                        api_responses.append((r.status_code, r.content))

                        r.close()

                        if r.status_code >= 200 and r.status_code < 400:
                            n_failed_requests = 0
                            break
                        else:
                            logging.error(
                                f"Failed to post {self.name} to Cybex API:\n{r.text}"
                            )
                            n_failed_requests += 1

                except requests.exceptions.ConnectionError as e:
                    logging.exception(f"Failed to post {self.name} to Cybex API")
                    n_failed_requests += 1

                exponential_backoff(n_failed_requests)

        return api_responses


class CybexSourceFetcher(threading.Thread):
    seconds_between_fetches = 10

    def __init__(self, cybex_source: CybexSource):
        super().__init__()
        self.source = cybex_source
        self.source_name = self.source.__class__.__name__

        if hasattr(cybex_source, "seconds_between_fetches"):
            self.seconds_between_fetches = cybex_source.seconds_between_fetches

        logging.info(
            f"plugin.{self.source_name}-- Applying rate limiting of {self.seconds between fetches} seconds between fetches"
        )

    def rate_limit(self, n_failed_queries):
        """ Can use more complicated limiting logic; sleep for now. """
        if n_failed_queries > 0:
            logging.warning(
                "plugin.{self.source_name}-- backing off exponentially due to failures."
            )
            exponential_backoff(n_failed_queries)
        else:
            logging.info(
                "plugin.{self.source_name}-- waiting for {self.seconds_between_fetches}."
            )
            time.sleep(self.seconds_between_fetches)

    def run(self):
        n_failed_queries = 0
        while True:
            try:
                logging.info(
                    f"Fetching vulnerability information from {self.source_name}."
                )
                # In general, we expect fetch and post to be atomic operations
                # If fetching from the vuln. data source OR posting fails, then
                # the entire operation raises and we retry with backoff. In fact,
                # some threat data sources (HoneyPot) only send data once,
                # requiring caching to make retries meaningful. However, if
                # fetch_and_post is implemented non-atomically (drops read-once
                # data or can succeed even if data is partially reported), then
                # we may report data to the Cybex API out-of-order or incompletely
                self.source.fetch_and_post()
                n_failed_queries = 0
            except Exception:
                logging.error(f"plugin.{self.source_name}-- ", exc_info=True)
                n_failed_queries += 1

            self.rate_limit(n_failed_queries)
