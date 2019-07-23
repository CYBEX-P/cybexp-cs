import sys, os
sys.path.append("../..")

# Import from lib
import pymongo, pytz, stix2, json
from flask_restful import Resource, reqparse
from flask_jwt_extended import jwt_required
##from dateutil.parser import parse as parse_time
##from datetime import datetime
from tahoe import get_backend

##os.environ["_MONGO_URL"] = "mongodb://cybexp3.acs.unr.edu:27017/?authSource=admin"
os.environ["_MONGO_URL"] = "mongodb://cybexp3.acs.unr.edu:27017/"
os.environ["_ANALYTICS_DB"] = "tahoe_db"
os.environ["_ANALYTICS_COLL"] = "instances"

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
    "comment",
    "cpe",
    "creation_date",
    "cryptocurrency_address",
    "cve_id",
    "data",
    "datetime",
    "description",
    "dns_soa_email",
    "domain",
    "email_addr",
    "email_attachment_name",
    "email_body",
    "email_display_name",
    "email_display_name",
    "email_reply_to",
    "filename",
    "filepath",
    "hash",
    "hex_data",
    "hostname",
    "http_user_agent",
    "id",
    "imphash",
    "ip",
    "ipv4",
    "jabber_id",
    "location",
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
    "pattern",
    "pattern_in_file",
    "pdb",
    "pehash",
    "phone_number",
    "port",
    "premium_rate_telephone_number",
    "prtn",
    "registrar",
    "regkey",
    "repository",
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
    "subject",
    "target_name",
    "text",
    "threat_actor_name",
    "twitter_id",
    "uri",
    "user_agent",
    "username",
    "vulnerability",
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

        
