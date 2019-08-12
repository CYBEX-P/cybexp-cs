#!/usr/bin/env python3
import logging, json, copy, pdb
from threading import Thread, active_count

import plugin


plugin_for_type = {
    "misp_api": plugin.MISPServerSource,
    "misp_file": plugin.MISPFileSource,
    "websocket": plugin.WebsocketSource,
    "phishtank": plugin.PhishtankSource,
}


def run_input_plugins():
    config_file = plugin.common.get_config_file("../input_config.json")
    api_config = config_file["api_srv"]

    for input_config in config_file["input"]:
        type = input_config["type"]
        input_plugin = plugin_for_type[type]

        if type == "misp_api":
            if not isinstance(input_config["orgs"], list):
                input_config["orgs"] = [input_config["orgs"]]

            for org in input_config["orgs"]:
                misp_server_source = input_plugin(api_config, input_config, misp_org=org)
                plugin.common.CybexSourceFetcher(misp_server_source).start()
        elif type == "misp_file":
            misp_file_dir = input_config['directory']
            misp_file_source = input_plugin(api_config, input_config, filename=misp_file_dir)
            plugin.common.CybexSourceFetcher(misp_file_source).start()
        else:
            plugin.common.CybexSourceFetcher(
                input_plugin(api_config, input_config)
            ).start()


if __name__ == "__main__":
    logging.basicConfig(
        filename = '../input.log',
        level=logging.DEBUG,
        format="%(asctime)s %(levelname)s:%(message)s",
    )  # filename = '../input.log',

    run_input_plugins()
