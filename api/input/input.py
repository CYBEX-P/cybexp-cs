# Configure Logging
import logging
logging.basicConfig(filename = 'input.log', level=logging.ERROR,
                    format='%(asctime)s %(message)s')
from threading import Thread
import builtins, json

import plugin

# Get plugin configuration
with open('../config.json') as json_conf:
    conf = json.load(json_conf)
builtins._CONF = conf

# Websocket Input Plugin
ws_p = Thread(target=plugin.ws_proc)
ws_p.start()

# MISP Input Plugin
misp_lst = []
for inp in _CONF['input']:
    if inp['type'] == 'misp-api':
        all_org = inp['org']
        misp_inst = plugin.MispInst(inp, all_org)
        misp_lst.append(misp_inst)

for misp_inst in misp_lst:
    misp_inst.run()
