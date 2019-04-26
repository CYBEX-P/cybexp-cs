# Import from ../cybexp_common
import sys
sys.path.append("../..")
from cybexp_common.load_cybexp_db import coll_or_fs
from cybexp_common.stix2ext import *

# Import from lib
import pymongo, pytz, stix2, json
from flask_restful import Resource, reqparse
from flask_jwt_extended import jwt_required
from dateutil.parser import parse as parse_time
from datetime import datetime

# Builtin variables
import builtins
builtins._PROJECTION = {"_id":0, "filters":0, "bad_data":0}
builtins._REPORT_ORGID = "identity--7f60ac36-74dd-4c23-bc31-3226533d93d2"
builtins._QLIM = 10000
builtins._DOCUMENTATION = "https://github.com/CYBEX-P/cybexp-cs/tree/master/api"
builtins._VALID_ATT = {'ip' : 'ipv4-addr',
                       'ipv4' : 'ipv4-addr',
                       'ipv4-addr' : 'ipv4-addr',
                       'url':'url',
                       'email' : 'email-addr',
                       'email-addr' : 'email-addr',
                       'domain-name' : 'domain-name',
                       'domain' : 'domain-name',
                       'mac-addr' : 'mac-addr',
                       'mac' : 'mac-addr',
                       'file' : 'file',
                       'file-hash' : 'file',
                       'file-sha256' : 'file',
                       'file-hash-sha256' : 'file'}
builtins._FUTURE_ATT = {'port' : 'port',
                        'btc' : 'btc',
                        'BTC' : 'btc',
                        'autonomous-system' : 'autonomous-system',
                        'AS' : 'autonomous-system',
                        'BGP' : 'bgp-path',
                        'bgp-path' : 'bgp-path',
                        'ssid' : 'ssid',
                        'comment' : 'comment'}

# Classes
class Report(Resource):
    def __init__(self, example):
        self.example = example
        self.response = {"example" : self.example, "documentation" : _DOCUMENTATION}
        self.status_code = 200
        self.request = {}
        self.obj_typ = None
        self.obj_val = None
        super().__init__()
    
    @jwt_required
    def valid_att(self, req_parser):
        self.request = req_parser.parse_args()
        request_keys = [ k for k in self.request.keys() if self.request[k]]
        valid_keys = _VALID_ATT.keys()
        future_keys = _FUTURE_ATT.keys()

        future_att = set(request_keys).intersection(future_keys)
        valid_att = set(request_keys).intersection(valid_keys)
        count = len(valid_att) + len(future_att)

        message = None
        if count < 1:  message, self.status_code = 'Input valid attribute object, check spelling', 400
        elif count > 1: message, self.status_code = 'Input one attribute object at a time', 400
        elif future_att:
            obj_typ = future_att.pop()
            self.obj_val = self.request[obj_typ]
            self.obj_typ = _FUTURE_ATT[obj_typ]
            self.response = {}
            message = self.obj_typ + ' object not found: ' + self.obj_val
        else:
            obj_typ = valid_att.pop()
            self.obj_val = self.request[obj_typ]
            self.obj_typ = _VALID_ATT[obj_typ]
            return True
        self.response['message'] = message
        return False
        
        
