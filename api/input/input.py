# Configure Logging
import logging, json, copy, pdb
from threading import Thread, active_count

import plugin

def input_main(config):
    # Websocket Input Plugin
    try:
        ws_p = Thread(target=plugin.ws_proc, args=(config,))
        ws_p.start()
    except Exception: logging.error("cybexp.api.input.input_main -- ", exc_info=True)
    # MISP API
    try:
        misp_p = Thread(target=plugin.misp_proc, args=(config,))
        misp_p.start()       
    except Exception: logging.error("cybexp.api.input.input_main -- ", exc_info=True)
    # MISP Json files 
    try:
        misp_file_p = Thread(target=plugin.misp_file_proc, args=(config,))
        misp_file_p.start()
    except Exception: logging.error("cybexp.api.input.input_main -- ", exc_info=True)


if __name__ == "__main__":
    logging.basicConfig(filename = '../input.log', level=logging.DEBUG, format='%(asctime)s %(levelname)s:%(message)s') # filename = '../input.log',

    with open("../input_config.json") as f: input_config = json.load(f)
    if not input_config: logging.warning("api.input.input -- No input configuration found")
    
    input_main(copy.deepcopy(input_config))
