import os, pdb, logging, pprint
from datetime import datetime as dt
from pymongo import MongoClient
from tahoe import get_backend, NoBackend, MongoBackend, Attribute, Object, Event, Session, parse

_PROJECTION = {"_id":0, "filters":0, "bad_data":0}
_VALID_ATT = ['ipv4', 'country_code3', 'longitude', 'region_name', 'city_name', 'region_code', 'country_name', 'latitude', 'timezone', 'continent_code', 'country_code2']

def filt_misp(backend=NoBackend()):
    try: 
        filt_id = "filter--c5ec01a3-f646-402e-92c9-e15c321a9653"
        query = {"raw_type":"x-misp-event", "filters":{"$ne": filt_id }, "_valid" : {"$ne" : False}}
        if os.getenv("_MONGO_URL"): backend = get_backend()
        cursor = backend.find(query, _PROJECTION)
        if not cursor: return False
        for raw in cursor:
            j = Misp(raw)
##            eventid = raw["data"]["eventid"]
##            if   eventid == "cowrie.client.kex": j = ClientKex(raw)  
##            elif eventid == "cowrie.client.size": j = ClientSize(raw)
##            else:
##                logging.warning("proc.analytics.filters.filt_cowrie.filt_cowrie: Unknown eventid: " + eventid)
##                continue
    except:
        logging.error("proc.analytics.analytics: ", exc_info=True)
##        backend.update_one( {"uuid" : raw["uuid"]}, {"$set" : {"_valid" : False}})
        return False
    else:
##        backend.update_one( {"uuid" : raw["uuid"]}, {"$addToSet": {"filters": filt_id} })
    return True

class Misp():
    def __init__(self):

        config = { 
		"mongo_url" : "mongodb://cybexp_user:CybExP_777@134.197.21.231:27017/?authSource=admin",
		"analytics_db" : "tahoe_db",
		"analytics_coll" : "instances"
            }
        os.environ["_MONGO_URL"] = config.pop("mongo_url")
        os.environ["_ANALYTICS_DB"] = config.pop("analytics_db", "tahoe_demo")
        os.environ["_ANALYTICS_COLL"] = config.pop("analytics_coll", "instances")
        self.raw, self.data, self.event_type = raw, raw["data"]["Event"], 'misp'
        self.orgid = self.raw["orgid"]
        self.timestamp = float(self.data["timestamp"])
        
    
        
        e = Event(self.event_type, self.orgid, self.objects, timestamp)



if __name__ == "__main__":
    config = { 
		"mongo_url" : "mongodb://cybexp_user:CybExP_777@134.197.21.231:27017/?authSource=admin",
		"analytics_db" : "tahoe_db",
		"analytics_coll" : "instances"
            }
    os.environ["_MONGO_URL"] = config.pop("mongo_url")
    os.environ["_ANALYTICS_DB"] = config.pop("analytics_db", "tahoe_db")
    os.environ["_ANALYTICS_COLL"] = config.pop("analytics_coll", "instances")

    filt_misp()













##
##
##class ClientKex(Cowrie):
##    def __init__(self, raw):
##        self.raw, self.data, self.event_type = raw, raw["data"], 'ssh_key_exchange'
##
##        encCS = [e.split('@')[0] for e in self.data["encCS"]]
##        enc_att = [Attribute('encr_algo', enc_algo) for enc_algo in encCS]
##        enc_obj = Object('encr_algo_set', enc_att)
##
##        compCS = self.data["compCS"]
##        if compCS: comp_att = [Attribute('comp_algo', comp_algo) for comp_algo in compCS]
##        else: comp_att = [Attribute('comp_algo', 'none')]
##        comp_obj = Object('comp_algo_set', comp_att)
##
##        kexAlgs = [e.split('@')[0] for e in self.data["kexAlgs"]]
##        kex_algo_att = [Attribute('kex_algo', kex_algo) for kex_algo in kexAlgs]
##        kex_obj = Object('kex_algo_set', kex_algo_att)
##
##        keyAlgs = [e.split('@')[0] for e in self.data["keyAlgs"]]
##        pub_key_algo_att = [Attribute('pub_key_algo', pub_key_algo) for pub_key_algo in keyAlgs]
##        pub_key_obj = Object('pub_key_algo_set', pub_key_algo_att)
##
##        macCS = [e.split('@')[0] for e in self.data["macCS"]]
##        mac_att = [Attribute('mac_algo', mac_algo) for mac_algo in macCS]
##        mac_obj = Object('mac_algo_set', mac_att)
##
##        hash_obj = Object('hash', Attribute('hash', self.data['hassh']))
##
##        self.objects = [enc_obj, comp_obj, kex_obj, pub_key_obj, mac_obj, hash_obj]
##        super().__init__()
##
##class ClientSize(Cowrie):
##    def __init__(self, raw):
##        self.raw, self.data, self.event_type = raw, raw["data"], 'ssh_client_size'
##        height_att = Attribute('height', self.data["height"])
##        width_att = Attribute('width', self.data["width"])
##        ssh_obj = Object('ssh_client_size', [height_att, width_att])
##        self.objects = [ssh_obj]
##        super().__init__()
##
##class ClientVar(Cowrie):
##    def __init__(self, raw):
##        self.raw, self.data, self.event_type = raw, raw["data"], 'ssh_client_env'
##        env_att = Attribute('text', self.data["msg"])
##        ssh_obj = Object('ssh_client_env', [env_att])
##        self.objects = [ssh_obj]
##        super().__init__()
##
##class ClientVersion(Cowrie):
##    def __init__(self, raw):
##        self.raw, self.data, self.event_type = raw, raw["data"], 'ssh_version'
##        ssh_version = self.data["version"]
##        if ssh_version[0] == "'": ssh_version = ssh_version.replace("'", "")
##        ssh_version_att = Attribute('ssh_version', ssh_version)
##        ssh_obj = Object('ssh_version', ssh_version_att)
##        self.objects = [ssh_obj]
##        super().__init__()
##
##
##class CommandInput(Cowrie):
##    def __init__(self, raw, objects=[]):
##        self.raw, self.data, self.event_type = raw, raw["data"], 'shell_command'
##        self.objects = objects + [ Object('shell_command', Attribute('text', self.data["command"])) ]
##        super().__init__()
##
##class CommandSuccess(CommandInput):
##    def __init__(self, raw):
##        objects = [Object('success', [Attribute('boolean', True)])]
##        super().__init__(raw, objects)
##
##class CommandFailed(CommandInput):
##    def __init__(self, raw):
##        objects = [Object('success', [Attribute('boolean', False)])]
##        super().__init__(raw, objects)
##
##class DirectTcpIp(Cowrie):
##    def __init__(self):
##        src_obj = Object('src', [Attribute('hostname', self.data['host']['name'])])
##        dst_obj = Object('dst', [Attribute('url', self.data["dst_ip"])])
##        dst_port_obj = Object('dst_port', [Attribute('port', self.data["dst_port"])])
##        protocol_obj = Object('protocol', [Attribute('protocol', "TCP")])
##
##        self.objects += [src_obj, dst_obj, dst_port_obj, protocol_obj]
##        super().__init__()
##
##class DirectTcpIpData(DirectTcpIp):
##    def __init__(self, raw):
##        self.raw, self.data, self.event_type = raw, raw["data"], 'network_traffic'
##        data_obj = Object('data', Attribute('data', self.data["data"]))
##        self.objects = [data_obj]
##        super().__init__()
##
##class DirectTcpIpRequest(DirectTcpIp):
##    def __init__(self, raw):
##        self.raw, self.data, self.event_type = raw, raw["data"], 'network_traffic'
##        src_port_obj = Object('src_port', [Attribute('port', self.data["src_port"])])
##        self.objects = [src_port_obj]
##        super().__init__()
##
##class Login(Cowrie):
##    def __init__(self):
##        login_obj = Object('login_credential', [Attribute('username', self.data["username"]),
##                                                Attribute('password', self.data["password"])])
##        self.objects += [login_obj]
##        super().__init__()
##
##class LoginFailed(Login):
##    def __init__(self, raw):
##        self.raw, self.data, self.event_type = raw, raw["data"], 'ssh_login' 
##        self.objects = [Object('success', [Attribute('boolean', False)])]
##        super().__init__()
##
##class LoginSuccess(Login):
##    def __init__(self, raw):
##        self.raw, self.data, self.event_type = raw, raw["data"], 'ssh_login' 
##        self.objects = [Object('success', [Attribute('boolean', True)])]
##        super().__init__()      
##        
##class SessionClosed(Cowrie):
##    def __init__(self, raw):
##        self.raw, self.data = raw, raw["data"]
##        session = self.get_session()
##        timestamp = self.data["@timestamp"]
##        end_time = dt.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp()
##        self.update = {"duration" : self.data["duration"], "end_time" : end_time}
##        session.update(self.update)
##                
##class SessionConnect(Cowrie):
##    def __init__(self, raw):
##        self.raw, self.data = raw, raw["data"]
##        session = self.get_session()
##        timestamp = self.data["@timestamp"]
##        start_time = dt.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp()
##        self.update = {"start_time" : start_time}
##        session.update(self.update)
##
##class SessionFileDownload(Cowrie):
##    def __init__(self, raw):
##        self.raw, self.data, self.event_type = raw, raw["data"], 'file_download'
##        self.objects = [Object('url', [Attribute('url', self.data['url'])])]
##        filename_att = Attribute('filename', self.data['url'].split('/')[-1])
##        try: sha256_att = Attribute('sha256', self.data['shasum'])
##        except: self.objects += [Object('file', [filename_att]), Object('success', [Attribute('boolean', False)])]
##        else: self.objects += [Object('file', [filename_att, sha256_att])]
##        super().__init__()
##
##
##    
##
##    
##
##
##    
##
