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

        
