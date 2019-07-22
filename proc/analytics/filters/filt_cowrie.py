import os, pdb, logging
from datetime import datetime as dt
from pymongo import MongoClient
from tahoe import get_backend, NoBackend, MongoBackend, Attribute, Object, Event, Session, parse

_PROJECTION = {"_id":0, "filters":0, "_valid":0}
_VALID_ATT = ['ipv4', 'country_code3', 'longitude', 'region_name', 'city_name', 'region_code', 'country_name', 'latitude', 'timezone', 'continent_code', 'country_code2']

def filt_cowrie(backend=NoBackend()):
    try: 
        filt_id = "filter--ad8c8d0c-0b25-4100-855e-06350a59750c"
        query = {"raw_type":"x-unr-honeypot", "filters":{"$ne":filt_id},
                 "data.eventid":{"$exists":True}, "_valid" : {"$ne" : False}}
        
        backend = get_backend() if os.getenv("_MONGO_URL") else NoBackend()
        cursor = backend.find(query, _PROJECTION)
        if not cursor: return False
        for raw in cursor:
            eventid = raw["data"]["eventid"]
            if   eventid == "cowrie.client.kex": j = ClientKex(raw)  
            elif eventid == "cowrie.client.size": j = ClientSize(raw)
            elif eventid == "cowrie.client.var": j = ClientVar(raw)
            elif eventid == "cowrie.client.version": j = ClientVersion(raw)
            elif eventid == "cowrie.command.failed": j = CommandInput(raw)
            elif eventid == "cowrie.command.input": j = CommandInput(raw)
            elif eventid == "cowrie.command.success": j = CommandInput(raw)
            elif eventid == "cowrie.direct-tcpip.data": j = DirectTcpIpData(raw) 
            elif eventid == "cowrie.direct-tcpip.request": j = DirectTcpIpRequest(raw)
            elif eventid == "cowrie.login.failed": j = LoginFailed(raw) 
            elif eventid == "cowrie.login.success": j = LoginSuccess(raw)
            elif eventid == "cowrie.session.closed": j = SessionClosed(raw)
            elif eventid == "cowrie.session.connect": j = SessionConnect(raw)
            elif eventid == "cowrie.session.file_download": j = SessionFileDownload(raw)
            elif eventid == "cowrie.session.file_download.failed": j = SessionFileDownload(raw)
            else:
                logging.warning("proc.analytics.filters.filt_cowrie.filt_cowrie: Unknown eventid: " + eventid)
                continue
    except:
        logging.error("proc.analytics.analytics: ", exc_info=True)
        pdb.set_trace()
##        backend.update_one( {"uuid" : raw["uuid"]}, {"$set" : {"_valid" : False}})
        return False
##    else:
##        backend.update_one( {"uuid" : raw["uuid"]}, {"$addToSet": {"filters": filt_id} })
    return True

class Cowrie():
    def __init__(self):
        self.orgid = self.raw["orgid"]
        timestamp = self.data["@timestamp"]
        timestamp = dt.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp()
        
        geoip_att = [Attribute(k, v) for k,v in self.data["geoip"].items() if k in  _VALID_ATT]
        attacker_ip_att = Attribute('ipv4', self.data["src_ip"])
        attacker_obj = Object('attacker', [attacker_ip_att] + geoip_att)
        self.objects.append(attacker_obj)
        
        e = Event(self.event_type, self.objects, self.orgid, timestamp, malicious=True)
        session = self.get_session()
        session.add_event(e)

    def get_session(self):
        sessionid = self.data['session']
        sessionid_att = Attribute('x_cowrie_sessionid', sessionid)
        hostname = self.data['host']['name']
        hostname_att = Attribute('hostname', hostname)
        session = Session('cowrie_session', [sessionid_att, hostname_att])
        return session

class ClientKex(Cowrie):
    def __init__(self, raw):
        self.raw, self.data, self.event_type = raw, raw["data"], 'ssh_key_exchange'

        encCS = [e.split('@')[0] for e in self.data["encCS"]]
        enc_algo = [Attribute('encr_algo', enc_algo) for enc_algo in encCS]

        compCS = self.data["compCS"]
        if compCS: comp_att = [Attribute('comp_algo', comp_algo) for comp_algo in compCS]
        else: comp_algo = [Attribute('comp_algo', 'none')]

        kexAlgs = [e.split('@')[0] for e in self.data["kexAlgs"]]
        kex_algo = [Attribute('kex_algo', kex_algo) for kex_algo in kexAlgs]


        keyAlgs = [e.split('@')[0] for e in self.data["keyAlgs"]]
        pub_key_algo = [Attribute('pub_key_algo', pub_key_algo) for pub_key_algo in keyAlgs]

        macCS = [e.split('@')[0] for e in self.data["macCS"]]
        mac_algo = [Attribute('mac_algo', mac_algo) for mac_algo in macCS]

        hash_att = Attribute('hash', self.data['hassh'])

        ssh_obj = Object('ssh', [enc_algo, comp_algo, kex_algo, pub_key_algo, mac_algo, hash_att])

        self.objects = [ssh_obj]
        super().__init__()

class ClientSize(Cowrie):
    def __init__(self, raw):
        self.raw, self.data, self.event_type = raw, raw["data"], 'ssh_client_size'
        height_att = Attribute('height', self.data["height"])
        width_att = Attribute('width', self.data["width"])
        client_size = Object('ssh_client_size', [height_att, width_att])
        ssh_obj = Object('ssh', client_size)
        self.objects = [ssh_obj]
        super().__init__()

class ClientVar(Cowrie):
    def __init__(self, raw):
        self.raw, self.data, self.event_type = raw, raw["data"], 'ssh_client_env'
        env_att = Attribute('ssh_client_env', self.data["msg"])
        ssh_obj = Object('ssh', [env_att])
        self.objects = [ssh_obj]
        super().__init__()

class ClientVersion(Cowrie):
    def __init__(self, raw):
        self.raw, self.data, self.event_type = raw, raw["data"], 'ssh_version'
        ssh_version = self.data["version"]
        if ssh_version[0] == "'": ssh_version = ssh_version.replace("'", "")
        ssh_version_att = Attribute('ssh_version', ssh_version)
        ssh_obj = Object('ssh', ssh_version_att)
        self.objects = [ssh_obj]
        super().__init__()


class CommandInput(Cowrie):
    def __init__(self, raw, objects=[]):
        self.raw, self.data, self.event_type = raw, raw["data"], 'shell_command'
        self.objects = objects + [Attribute('shell_command', self.data["command"])]
        super().__init__()

class CommandSuccess(CommandInput):
    def __init__(self, raw):
        objects = [Attribute('success', True)]
        super().__init__(raw, objects)

class CommandFailed(CommandInput):
    def __init__(self, raw):
        objects = [Attribute('success', False)]
        super().__init__(raw, objects)

class DirectTcpIp(Cowrie):
    def __init__(self):
        src_att = Attribute('hostname', self.data['host']['name'])
        src_obj = Object('src', src_att)
        
        dst_att = Attribute('url', self.data["dst_ip"])
        dport_att = Attribute('port', self.data["dst_port"])
        dst_obj = Object('dst', [dst_att, dport_att])

        protocol_att = Attribute("protocol", "TCP")

        self.objects += [src_obj, dst_obj, protocol_att]
        super().__init__()

class DirectTcpIpData(DirectTcpIp):
    def __init__(self, raw):
        self.raw, self.data, self.event_type = raw, raw["data"], 'network_traffic'
        data_att = Attribute('data', self.data["data"])
        self.objects = [data_att]
        super().__init__()

class DirectTcpIpRequest(DirectTcpIp):
    def __init__(self, raw):
        self.raw, self.data, self.event_type = raw, raw["data"], 'network_traffic'
        src_port_obj = Object('src', [Attribute('port', self.data["src_port"])])
        self.objects = [src_port_obj]
        super().__init__()

class Login(Cowrie):
    def __init__(self):
        login_obj = Object('login_credential', [Attribute('username', self.data["username"]),
                                                Attribute('password', self.data["password"])])
        self.objects += [login_obj]
        super().__init__()

class LoginFailed(Login):
    def __init__(self, raw):
        self.raw, self.data, self.event_type = raw, raw["data"], 'ssh_login' 
        self.objects = [Attribute('success', False)]
        super().__init__()

class LoginSuccess(Login):
    def __init__(self, raw):
        self.raw, self.data, self.event_type = raw, raw["data"], 'ssh_login' 
        self.objects = [Attribute('sucess', True)]
        super().__init__()      
        
class SessionClosed(Cowrie):
    def __init__(self, raw):
        self.raw, self.data = raw, raw["data"]
        session = self.get_session()
        timestamp = self.data["@timestamp"]
        end_time = dt.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp()
        self.update = {"duration" : self.data["duration"], "end_time" : end_time}
        session.update(self.update)
                
class SessionConnect(Cowrie):
    def __init__(self, raw):
        self.raw, self.data = raw, raw["data"]
        session = self.get_session()
        timestamp = self.data["@timestamp"]
        start_time = dt.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp()
        self.update = {"start_time" : start_time}
        session.update(self.update)

class SessionFileDownload(Cowrie):
    def __init__(self, raw):
        self.raw, self.data, self.event_type = raw, raw["data"], 'file_download'
        self.objects = [Attribute('url', self.data['url'])]
        filename_att = Attribute('filename', self.data['url'].split('/')[-1])
        try: sha256_att = Attribute('sha256', self.data['shasum'])
        except: self.objects += [Object('file', [filename_att]), Attribute('success', False)]
        else: self.objects += [Object('file', [filename_att, sha256_att])]
        super().__init__()


    

if __name__ == "__main__":
    config = { 
		"mongo_url" : "mongodb://cybexp_user:CybExP_777@134.197.21.231:27017/?authSource=admin",
##                "mongo_url" : "mongodb://localhost:27017",
		"analytics_db" : "tahoe_db",
##                "analytics_db" : "tahoe_demo",
		"analytics_coll" : "instances"
            }
    os.environ["_MONGO_URL"] = config.pop("mongo_url")
    os.environ["_ANALYTICS_DB"] = config.pop("analytics_db", "tahoe_db")
    os.environ["_ANALYTICS_COLL"] = config.pop("analytics_coll", "instances")

    filt_cowrie()    


    

