# Configure Logging
import logging, json, copy, pdb
from threading import Thread, active_count

import plugin

def input_main(config):
    try:
        # Websocket Input Plugin
        ws_p = Thread(target=plugin.ws_proc, args=(config,))
        ws_p.start()

        # MISP  Input Plugin
##        for inp in 
        
    except Exception: logging.error("Exception in archive()", exc_info=True)
    
### Get plugin configuration
##with open('../config.json') as json_conf:
##    conf = json.load(json_conf)
##builtins._CONF = conf
##
### MISP Input Plugin
##misp_lst = []
##for inp in _CONF['input']:
##    if inp['type'] == 'misp-api':
##        all_org = inp['org']
##        misp_inst = plugin.MispInst(inp, all_org)
##        misp_lst.append(misp_inst)
##
##for misp_inst in misp_lst:
##    misp_inst.run()


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s:%(message)s') # filename = '../input.log',

    with open("../input_config.json") as f: input_config = json.load(f)
    if not input_config: logging.warning("input.py: No input configuration found")
    
    input_main(copy.deepcopy(input_config))
