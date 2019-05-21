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
                       'file-hash-sha256' : 'file',
                       'network' : 'ipv4-addr'}
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
        self.empty_stix2_bundle = json.loads(stix2.Bundle().serialize())
        self.empty_stix2_bundle['objects'] = []
        self.example = example
        self.response = {"example" : self.example, "documentation" : _DOCUMENTATION}
        self.status_code = 200
        self.request = {}
        self.obj_typ = None
        self.obj_val = None
        tzname = None
        from_datetime = None
        to_datetime = None
        query = {}
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
        if count < 1:  message, self.status_code = 'Input valid attribute object, check spelling', 422
        elif count > 1: message, self.status_code = 'Input one attribute object at a time', 422
        elif future_att:
            obj_typ = future_att.pop()
            self.obj_val = self.request[obj_typ]
            self.obj_typ = _FUTURE_ATT[obj_typ]
            self.response = {}
            message = self.empty_stix2_bundle
        else:
            obj_typ = valid_att.pop()
            self.obj_val = self.request[obj_typ]
            self.obj_typ = _VALID_ATT[obj_typ]
            return True
        self.response['message'] = message
        return False

    def qadd_dtrange(self):
        utc = pytz.utc
        tzname = self.tzname
        from_datetime = self.from_datetime
        to_datetime =self.to_datetime
        
        if not tzname: tzname = 'UTC'
        try: tz = pytz.timezone(tzname)
        except pytz.UnknownTimeZoneError:
            self.response['message'], self.status_code = 'Unknown Timezone : ' + tzname, 422 
            return False
        
        if from_datetime:
            try: from_datetime = parse_time(from_datetime)
            except ValueError:
                self.response['message'], self.status_code = 'Invalid from-time : ' + from_datetime, 422 
                return False
            from_datetime = tz.localize(from_datetime).astimezone(utc)
            self.query["$and"].append({"x_first_observed": {"$gte": from_datetime}})

        if to_datetime:
            try: to_datetime = parse_time(to_datetime)
            except:
                self.response['message'], self.status_code = 'Invalid to-time : ' + to_datetime, 422 
                return False
            to_datetime = tz.localize(to_datetime).astimezone(utc)
            try: self.query["$and"][2]["x_first_observed"]["$lte"] = to_datetime
            except IndexError: self.query["$and"].append({"x_first_observed": {"$lte": to_datetime}})

        return True
        
        
