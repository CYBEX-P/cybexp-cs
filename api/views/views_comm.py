# Import from ../cybexp_common
import sys
sys.path.append("../..")
from cybexp_common.load_cybexp_db import coll_or_fs
from cybexp_common.stix2ext import *

#Import from lib
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
