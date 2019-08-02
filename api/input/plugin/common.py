# Imports
import datetime, re, requests, json, time, urllib, threading, logging, random, copy, os, pdb, uuid

class BadConfig(Exception):
    pass


def get_config_file(filename="../../input_config.json"):
    with open(filename) as f:
        config_file = json.load(f) 

    def validate(config_file):
        # Validate config file
        _api_srv = config_file["api_srv"]

        if not _api_srv or not isinstance(_api_srv, dict) or ('url', 'token') - _api_srv.keys():
            raise BadConfig("Couldn't find cybexp1 (app server) info in the config.")

        _input = config_file["input"]

        if not _input or not isinstance(_input, list):
            raise BadConfig("Config doesn't have Cybex vulnerability source information.")

    validate(config_file)
    
    return config_file
    


def config_for_source_type(config_file, source_type, ndx=0):
    """ Get configuration from JSON for `source_type`. 

    Some source types can have multiple possible configs;
        disambiguate with an index.
    """

    i = 0
    for config in config_file["input"]:
        if config["type"] == source_type:
            if i == ndx:
                return config
            i += 1
    
    raise BadConfig(f"Didn't find the #{ndx} config for source type {source_type}")


def exponential_backoff(n):
    s = max(3600, (2 ** n) + (random.randint(0, 1000) / 1000))
    resume_time = (datetime.datetime.now() + datetime.timedelta(seconds=s)).strftime('%I:%M:%S %p')
    logging.error(f"Sleeping for {s} seconds, will resume around {resume_time}.")
    time.sleep(s)


# Classes
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

        self.post_url = api_config["url"] + "/api/v1.0/event"
        self.token = api_config["token"]

    def __str__(self):
        return('Cybexp Input, api server = {}, post url = {}'.format(
            self.api_srv, self.post_url))
               
    def fetch(self):
        """ Fetch vulnerability data from this Cybex source. """
        raise NotImplementedError

    def post_event_to_cybex_api(self, events):
        """ Post an event from the Cybex source to the Cybex API. """
        if type(events) != list: events = [events]
        api_responses = []

        logging.info(f"Posting {len(events)} events to Cybex API.")
        for event in events: 
            if isinstance(event, dict): event = json.dumps(event)
            data = event.encode()
            files = {'file' : data}
            headers={'Authorization': 'Bearer '+ self.token}

            while True:
                n_failed_requests = 0
                try:
                    with requests.post(self.post_url, files=files, headers=headers, data = {
                    'orgid': self.orgid, 'typtag': self.typtag, 'timezone': self.timezone}) as r:
                        api_responses.append((r.status_code, r.content))

                        r.close()

                        if r.status_code >= 200 and r.status_code < 400:
                            n_failed_requests = 0
                            break
                        else:
                            logging.error("Failed to post to Cybex API:\n" + r.text)
                            n_failed_requests += 1

                except requests.exceptions.ConnectionError as e:
                    logging.exception("Failed to post to Cybex API")
                    n_failed_requests += 1

                exponential_backoff(n_failed_requests)
            
        return api_responses
    


class CybexSourceFetcher(threading.Thread):
    seconds_between_fetches = 10

    def __init__(self, cybex_source: CybexSource, seconds_between_fetches=None, max_daily_fetches=None):
        super().__init__()
        self.source = cybex_source
        self.source_name = self.source.__class__.__name__
        
        if seconds_between_fetches:
            self.seconds_between_fetches = seconds_between_fetches
        elif max_daily_fetches:
            self.seconds_between_fetches = 60 * 60 * 24 / max_daily_fetches


    def rate_limit(self, n_failed_queries):
        """ Can use more complicated limiting logic; sleep for now. """
        if n_failed_queries > 0:
            exponential_backoff(n_failed_queries)
        else:
            time.sleep(self.seconds_between_fetches)


    def run(self):
        n_failed_queries = 0
        while True:
            try:
                logging.info(f"Fetching vulnerability information from {self.source_name}.")
                self.source.fetch()
                n_failed_queries = 0
            except Exception:
                logging.error(f"plugin.{self.source_name}-- ", exc_info=True)
                n_failed_queries += 1

            self.rate_limit(n_failed_queries)

