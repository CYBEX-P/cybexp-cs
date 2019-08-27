#!/usr/bin/env python3
import argparse
import json
import logging
from pathlib import Path
from typing import Collection

import plugin

plugin_for_type = {
    "misp_api": plugin.MISPServerSource,
    "misp_file": plugin.MISPFileSource,
    "websocket": plugin.WebsocketSource,
    "phishtank": plugin.PhishtankSource,
}


class NoSuchPlugin(Exception):
    pass


def get_config_file(filename="../config.json"):
    with open(filename) as f:
        config_file = json.load(f)

    def validate(config_file):
        # Validate configuration for posting to Cybex-P API
        _api_srv = config_file["api_srv"]

        if (
            not _api_srv
            or not isinstance(_api_srv, dict)
            or ("url", "token") - _api_srv.keys()
        ):
            raise BadConfig("Couldn't find cybexp1 (app server) info in the config.")

        _input = config_file["input"]

        if not _input or not isinstance(_input, list):
            raise BadConfig(
                "Config doesn't have Cybex vulnerability source information."
            )

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


def run_input_plugins(plugins_to_run: Collection[str]):
    config_file = get_config_file("config.json")
    api_config = config_file["api_srv"]

    for input_config in config_file["input"]:
        type = input_config["type"]

        if type not in plugins_to_run:
            continue

        input_plugin = plugin_for_type[type]

        if type == "misp_api":
            if not isinstance(input_config["orgs"], list):
                input_config["orgs"] = [input_config["orgs"]]

            for org in input_config["orgs"]:
                misp_server_source = input_plugin(
                    api_config, input_config, misp_org=org
                )
                plugin.common.CybexSourceFetcher(misp_server_source).start()
        elif type == "misp_file":
            misp_file_dir = input_config["directory"]
            misp_file_source = input_plugin(
                api_config, input_config, filename=misp_file_dir
            )
            plugin.common.CybexSourceFetcher(misp_file_source).start()
        else:
            plugin.common.CybexSourceFetcher(
                input_plugin(api_config, input_config)
            ).start()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    # By default, run all input plugins
    parser.add_argument(
        "-p",
        "--plugins",
        nargs="+",
        help="Names of plugin types to run.",
        default=plugin_for_type.keys(),
    )
    args = parser.parse_args()

    for p in args.plugins:
        if p not in plugin_for_type:
            raise NoSuchPlugin(f"{p} isn't a valid plugin.")

    # Set this up after argparse since it may be helpful to get those errors
    # back to stdout
    logfile = Path("/var/log/cybexp/input.log")
    print(f"Setting up logging to {logfile}")
    logfile.parent.mkdir(parents=True, exist_ok=True, mode=0o777)
    logfile.touch(exist_ok=True, mode=0o666)

    logging.basicConfig(
        filename=logfile,
        level=logging.DEBUG,
        format="%(asctime)s %(levelname)s:%(message)s",
    )
    
    logging.info("Starting CTI collector...")
    logging.info(f"Running the following plugins: {args.plugins}")

    run_input_plugins(args.plugins)
