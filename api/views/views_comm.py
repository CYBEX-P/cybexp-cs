import pymongo, pytz, stix2, json, os, time, pdb
from flask_restful import Resource, reqparse
from flask_jwt_extended import jwt_required
from dateutil.parser import parse as parse_time

os.environ["_MONGO_URL"] = "mongodb://cybexp_user:CybExP_777@134.197.21.231:27017/?authSource=admin"
os.environ["_TAHOE_DB"] = "tahoe_db"
os.environ["_TAHOE_COLL"] = "instances"

from tahoe import get_backend

# Builtin variables
import builtins
builtins.backend = get_backend()
builtins._PROJECTION = {"_id":0, "filters":0, "bad_data":0}
builtins._REPORT_ORGID = "identity--7f60ac36-74dd-4c23-bc31-3226533d93d2"
builtins._QLIM = 10000
builtins._DOCUMENTATION = "https://github.com/CYBEX-P/cybexp-cs/tree/master/api"
builtins._VALID_ATT = [
    "AS",
    "asn",
    "btc",
    "bytes",
    "campaign_id",
    "campaign_name",
    "checksum",
    "city_name",
    "comment",
    "comp_algo",
    "continent_code",
    "country_code2",
    "country_code3",
    "country_name",
    "cpe",
    "creation_date",
    "cryptocurrency_address",
    "cve_id",
    "data",
    "datetime",
    "description",
    "dma_code",
    "dns_soa_email",
    "domain",
    "email_addr",
    "email_attachment_name",
    "email_body",
    "email_display_name",
    "email_reply_to",
    "encr_algo",
    "filename",
    "filepath",
    "hash",
    "height",
    "hex_data",
    "hostname",
    "http_user_agent",
    "id",
    "imphash",
    "ip",
    "ipv4",
    "jabber_id",
    "kex_algo",
    "latitude",
    "location",
    "longitude",
    "mac_algo",
    "machine_name",
    "md5",
    "message_id",
    "mime_boundary",
    "misp alias",
    "mobile_app_id",
    "mutex",
    "name",
    "named_pipe",
    "nids",
    "organization",
    "other",
    "password",
    "pattern",
    "pattern_in_file",
    "pdb",
    "pehash",
    "phone_number",
    "port",
    "postal_code",
    "premium_rate_telephone_number",
    "protocol",
    "prtn",
    "pub_key_algo",
    "region_code",
    "region_name",
    "registrar",
    "regkey",
    "repository",
    "sessionid",
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512",
    "sha512/224",
    "sha512/256",
    "shell_command",
    "sigma",
    "size_in_bytes",
    "snort",
    "ssdeep",
    "ssh_client_env",
    "ssh_version",
    "subject",
    "success",
    "target_name",
    "text",
    "threat_actor_name",
    "timezone",
    "twitter_id",
    "uri",
    "url",
    "user_agent",
    "username",
    "vulnerability",
    "width"
    "win_scheduled_task",
    "win_service_displayname",
    "win_service_name",
    "x509_fingerprint",
    "x509_fingerprint_md5",
    "x509_fingerprint_sha1",
    "x509_fingerprint_sha256",
    "x_mailer",
    "x_misp_target_external",
    "x_misp_target_location",
    "x_misp_target_org",
    "x_misp_target_user",
    "yara"
]

builtins._TEST_ATT = [
    "country_name-t",
    "file-t",
    "filename-t",
    "hostname-t",
    "ipv4-t",
    "port-t",
    "protocol-t",
    "sha256-t",
    "url-t"
]



common_parser = reqparse.RequestParser()
common_parser.add_argument('last')
common_parser.add_argument('from')
common_parser.add_argument('to')
common_parser.add_argument('tzname')


class CybResource(Resource):
    def __init__(self, *args, **kwargs):
        self.sub_type = kwargs.pop('sub_type', None)
        self.report_id = kwargs.pop('report_id', None)
        self.uuid = kwargs.pop('uuid', None)
        
        self.tzname = 'UTC'
        r = self.get_dtrange()

    @jwt_required
    def get(self): return self.getorpost()

    @jwt_required
    def post(self): return self.getorpost()

    def getorpost(self):
        return "getorpost() method not implemented", 501

    def get_level_page(self):
        rprsr = reqparse.RequestParser()
        rprsr.add_argument('level', type=int)
        rprsr.add_argument('page', type=int)

        req = rprsr.parse_args()
        req = {k:v for k,v in req.items() if v is not None}

        self.lvl = req.pop('level', 1)
        self.page = req.pop('page', 1)

        if self.lvl < 1 or self.page < 1:
            self.error, self.status = 'Minimum value for level or page is 1', 422 
        

    def get_dtrange(self):
        req = common_parser.parse_args()

        utc = pytz.utc
        self.start = 0.0
        self.end = time.time()
        self.dtreq = False

        last = req['last']
        start = req['from']
        end = req['to']
        tzname = req['tzname']

        if last or start or end: self.dtreq = True
        if (last and start) or (last and end):
            self.error, self.status = 'Do not specify "last" with "from" or "to"', 422 
            return False

        def tosec(s):
            spu = {"s":1, #"sec":1, "second":1, "seconds":1,
                   "m":60, #"min":60, "mins":60, "minute":60, "minutes":60,
                   "h":3600, #"hr":3600, "hrs":3600, "hour":3600, "hours":3600
                   "d":86400, #"day":86400, "days":86400,
                   "w":604800, #"week":604800, "weeks":604800,
                   "M":2629800, #"month":2629800, "months":2629800
                   "Y":31557600} #"year":31557600, "years":31557600}
            return int(s[:-1]) * spu[s[-1]]
                
        if last:
            try:
               self.start = self.end - tosec(last)
            except:
                self.error, self.status = 'Invalid value for last: ' + last, 422 
                return False

        if tzname: self.tzname = tzname
        try: self.tz = pytz.timezone(self.tzname)
        except pytz.UnknownTimeZoneError:
            self.error, self.status = 'Unknown Timezone Name : ' + tzname, 422 
            return False

        if start:
            try: self.start = float(start)
            except ValueError:
                start = parse_time(start)
                self.start = self.tz.localize(start).astimezone(utc).timestamp()
            except ValueError:
                self.error, self.status = 'Invalid from-time : ' + start, 422 
                return False
            

        if end:
            try: self.end = float(end)
            except ValueError:
                end = parse_time(end)
                self.end = self.tz.localize(end).astimezone(utc).timestamp()
            except ValueError:
                self.error, self.status = 'Invalid to-time : ' + end, 422 
                return False
            
        return True

    def return_format(self, data):
        return {
            'itype': 'report', 'sub_type' : self.sub_type,
            'orgid' : _REPORT_ORGID, 'timestamp':time.time(),
            'uuid' : self.uuid, 'report_id' : self.report_id,
            'data' : data
        }

    def return_format_paginated(self, data, curpg, nxtpg):
        if not data: self.status = 205
        else: self.status = 206
        
        return {
            'itype': 'report', 'sub_type' : self.sub_type,
            'orgid' : _REPORT_ORGID, 'timestamp':time.time(),
            'uuid' : self.uuid, 'report_id' : self.report_id,
            'current_page' : curpg, 'next_page' : nxtpg,
            'data' : data,
        }



from tahoe import Attribute

attprsr = reqparse.RequestParser()
for att_type in _VALID_ATT: attprsr.add_argument(att_type)
for att_type in _TEST_ATT: attprsr.add_argument(att_type)

class AttReport(CybResource):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        req = attprsr.parse_args()
        req = {k:v for k,v in req.items() if v is not None}
        remaining_items = list(req.items())

        if len(remaining_items) != 1:
            self.error = 'Invalid or missing or multiple att_type, example:{"ip":"1.1.1.1"}'
            self.status = 400
            return

        att_type, data = remaining_items[0]
        self.att = Attribute(att_type, data)

        self.status = 200
        
