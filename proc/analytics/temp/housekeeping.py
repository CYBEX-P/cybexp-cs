import sys
sys.path.append("..")
from common.loaddb import loaddb
from common.schema.stix2ext import *
import stix2, json, time
from pprint import pprint
from dateutil.parser import parse as parse_time

db = loaddb('archive')
acoll = db.analytics

_ANALYTICS_ORGID = "identity--63476b91-c478-42b6-a554-a32b02836dc0"
_EIDS = ['cowrie.direct-tcpip.request', 'cowrie.login.failed', 'cowrie.session.closed', 'cowrie.client.kex', 'cowrie.client.version', 'cowrie.session.connect', 'cowrie.login.success', 'cowrie.direct-tcpip.data', 'cowrie.command.input', 'cowrie.command.success', 'cowrie.command.failed', 'cowrie.session.file_download', 'cowrie.log.closed', 'cowrie.session.params', 'cowrie.session.file_download.failed', 'cowrie.client.size', 'cowrie.client.var']
_QLIM = 100
_PROJECTION = {"_id":0, "filters":0, "bad_data":0}

def add_datetime_2_stix2():
    r = acoll.find({"x_first_observed" : {"$exists" : False}})
    for din_json in r:
        x_first_observed = parse_time(din_json["first_observed"])
        i = acoll.update_one( {"id" : din_json["id"]},
                         { "$set": {"x_first_observed":x_first_observed}})
        import pdb
        pdb.set_trace()
