import os, logging, time, pdb
from copy import deepcopy
from datetime import datetime as dt

if __name__ == "__main__": from demo_env import *
    
from tahoe import get_backend, NoBackend, Attribute, Object, Event, Session, parse

_PROJECTION = {"_id":0, "filters":0, "_valid":0}
_GEOIP_ATT = ["city_name", "continent_code", "country_code2", "country_code3", "country_name",
              "dma_code", "ip", "latitude", "longitude", "postal_code", "region_code", "region_name", "timezone"]

def filt_cowrie(backend=NoBackend()):
    try: 
        filt_id = "filter--ad8c8d0c-0b25-4100-855e-06350a59750c"
        if os.getenv("_MONGO_URL"): backend = get_backend()
        
        query = {"itype":"raw", "sub_type":"x-unr-honeypot",
                 "filters":{"$ne":filt_id}, "_valid" : {"$ne" : False},
                 "data.eventid":{"$exists":True}}
        cursor = backend.find(query, _PROJECTION, no_cursor_timeout=True)
        if not cursor: logging.error("filt_cowrie: This should not happen")

        any_success = False
        for raw in cursor:
            try:
                eventid = raw["data"]["eventid"]
                timestamp = raw["data"]["@timestamp"]
                
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
                    logging.warning("filt_cowrie 0: Unknown eventid: " + eventid)
            except (KeyboardInterrupt, SystemExit): raise
            except:
                logging.error("\nfilt_cowrie 1: eventid: " + eventid +
                              ", timestamp: " + timestamp + "\n", exc_info=True)
##                backend.update_one( {"uuid" : raw["uuid"]}, {"$set" : {"_valid" : False}})
                j = False
            else: 
                backend.update_one({"uuid":raw["uuid"]}, {"$addToSet":{"filters":filt_id}})
            any_success = any_success or bool(j)

    except:
        logging.error("filt_cowrie 2: ", exc_info=True)
        return False
    return any_success


class Cowrie():
    def __init__(self):
        self.orgid = self.raw["orgid"]
        timestamp = self.raw_data["@timestamp"]
        timestamp = dt.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp()

        if not hasattr(self, "mal_data"): self.mal_data = []
        
        attacker_ip_att = Attribute('ipv4', self.raw_data["src_ip"], alias=['attacker_ip'])
        attacker_obj_data = [attacker_ip_att]

        if "geoip" in self.raw_data["tags"]:
            geoip_att = [Attribute(k, v) for k,v in self.raw_data["geoip"].items() if k in  _GEOIP_ATT]
            geoip_obj = Object('geoip', geoip_att)
            attacker_obj_data += [geoip_obj]
            self.mal_data += geoip_att
            
        attacker_obj = Object('attacker', attacker_obj_data)

        self.data.append(attacker_obj)
        self.mal_data += [attacker_ip_att, attacker_obj]

        e = Event(self.event_type, self.data, self.orgid, timestamp, malicious=True, mal_data = self.mal_data)

        session = self.get_session()
        session.add_event(e)

        raw = parse(self.raw)
        ref_uuid_list = e.related_uuid() + [session.uuid]
        raw.update_ref(ref_uuid_list)

    def get_session(self):
        sessionid = self.raw_data['session']
        sessionid_att = Attribute('sessionid', sessionid, alias=['x_cowrie_sessionid'])
        hostname = self.raw_data['host']['name']
        hostname_att = Attribute('hostname', hostname)
        session = Session('cowrie_session', [sessionid_att, hostname_att])
        return session

class ClientKex(Cowrie):
    def __init__(self, raw):
        self.event_type = 'ssh'
        self.raw_data, self.raw = raw.pop("data"), raw

        encCS = [e.split('@')[0] for e in self.raw_data["encCS"]]
        enc_algo = [Attribute('encr_algo', enc_algo) for enc_algo in encCS]

        compCS = self.raw_data["compCS"]
        if compCS: comp_algo = [Attribute('comp_algo', comp_algo) for comp_algo in compCS]
        else: comp_algo = [Attribute('comp_algo', 'none')]

        kexAlgs = [e.split('@')[0] for e in self.raw_data["kexAlgs"]]
        kex_algo = [Attribute('kex_algo', kex_algo) for kex_algo in kexAlgs]

        keyAlgs = [e.split('@')[0] for e in self.raw_data["keyAlgs"]]
        pub_key_algo = [Attribute('pub_key_algo', pub_key_algo) for pub_key_algo in keyAlgs]

        macCS = [e.split('@')[0] for e in self.raw_data["macCS"]]
        mac_algo = [Attribute('mac_algo', mac_algo) for mac_algo in macCS]

        hash_att = Attribute('hash', self.raw_data['hassh'], alias=['ssh_kex_hash'])

        ssh_obj = Object('ssh_key_exchange', enc_algo + comp_algo + kex_algo + pub_key_algo + mac_algo + [hash_att])

        self.data = [ssh_obj]
        self.mal_data = [hash_att]
        super().__init__()

class ClientSize(Cowrie):
    def __init__(self, raw):
        self.event_type = 'ssh'
        self.raw_data, self.raw = raw.pop("data"), raw
        height_att = Attribute('height', self.raw_data["height"])
        width_att = Attribute('width', self.raw_data["width"])
        ssh_client_size_obj = Object('ssh_client_size', [height_att, width_att])
        self.data = [ssh_client_size_obj]
        self.mal_data = [ssh_client_size_obj]
        super().__init__()

class ClientVar(Cowrie):
    def __init__(self, raw):
        self.event_type = 'ssh'
        self.raw_data, self.raw = raw.pop("data"), raw
        env_att = Attribute('ssh_client_env', self.raw_data["msg"])
        self.data = [env_att]
        self.mal_data = [env_att]
        super().__init__()

class ClientVersion(Cowrie):
    def __init__(self, raw):
        self.event_type = 'ssh'
        self.raw_data, self.raw = raw.pop("data"), raw
        ssh_version = self.raw_data["version"]
        if ssh_version[0] == "'": ssh_version = ssh_version.replace("'", "")
        ssh_version_att = Attribute('ssh_version', ssh_version)
        self.data = [ssh_version_att]
        super().__init__()


class CommandInput(Cowrie):
    def __init__(self, raw, objects=[]):
        self.event_type = 'shell_command'
        self.raw_data, self.raw = raw.pop("data"), raw
        command_att = Attribute('shell_command', self.raw_data["command"])
        self.data = objects + [command_att]
        self.mal_data = [command_att]
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
        src_att = Attribute('hostname', self.raw_data['host']['name'])
        src_obj = Object('src', src_att)
        
        url_att = Attribute('url', self.raw_data["dst_ip"])
        dport_att = Attribute('port', self.raw_data["dst_port"])
        dst_obj = Object('dst', [url_att, dport_att])

        protocol_att = Attribute("protocol", "TCP")

        self.data += [src_obj, dst_obj, protocol_att]
        super().__init__()

class DirectTcpIpData(DirectTcpIp):
    def __init__(self, raw):
        self.event_type = 'network_traffic'
        self.raw_data, self.raw = raw.pop("data"), raw
        data_att = Attribute('data', self.raw_data["data"])
        self.data = [data_att]
        super().__init__()

class DirectTcpIpRequest(DirectTcpIp):
    def __init__(self, raw):
        self.event_type = 'network_traffic'
        self.raw_data, self.raw = raw.pop("data"), raw
        sport_att = Attribute('port', self.raw_data["src_port"])
        src_obj = Object('src', [sport_att])
        self.data = [src_obj]
        super().__init__()


class Login(Cowrie):
    def __init__(self):
        username_att = Attribute('username', self.raw_data["username"])
        password_att = Attribute('password', self.raw_data["password"])
        login_obj = Object('login_credential', [username_att, password_att])
        self.data += [login_obj]
        self.mal_data = [username_att, password_att, login_obj]
        super().__init__()

class LoginFailed(Login):
    def __init__(self, raw):
        self.event_type = 'ssh'
        self.raw_data, self.raw = raw.pop("data"), raw
        self.data = [Attribute('success', False)]
        super().__init__()

class LoginSuccess(Login):
    def __init__(self, raw):
        self.event_type = 'ssh'
        self.raw_data, self.raw = raw.pop("data"), raw
        self.data = [Attribute('success', True)]
        super().__init__()      

        
class SessionClosed(Cowrie):
    def __init__(self, raw):
        self.raw_data, self.raw = raw.pop("data"), raw
        session = self.get_session()
        timestamp = self.raw_data["@timestamp"]
        end_time = dt.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp()
        update = {"duration" : self.raw_data["duration"], "end_time" : end_time}
        session.update(update)
                
class SessionConnect(Cowrie):
    def __init__(self, raw):
        self.raw_data, self.raw = raw.pop("data"), raw
        session = self.get_session()
        timestamp = self.raw_data["@timestamp"]
        start_time = dt.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp()
        update = {"start_time" : start_time}
        session.update(update)


class SessionFileDownload(Cowrie):
    def __init__(self, raw):
        self.event_type = 'file_download'
        self.raw_data, self.raw = raw.pop("data"), raw

        url = self.raw_data['url'].strip()
        filename = url.split('/')[-1].strip()
        
        url_att = Attribute('url', url)
        filename_att = Attribute('filename', filename)

        try:
            sha256_att = Attribute('sha256', self.raw_data['shasum'])
            file_obj = Object('file', [filename_att, sha256_att])
        except:
            success_att = Attribute('success', False)
            file_obj = Object('file', [filename_att, success_att])

        self.data = [url_att, file_obj]

        self.mal_data = [url_att, filename_att, file_obj]
        try: self.mal_data += [sha256_att]
        except: pass
        
        super().__init__()


    


##if __name__ == "__main__":
##    config = { 
##		"mongo_url" : "mongodb://cybexp_user:CybExP_777@134.197.21.231:27017/?authSource=admin",
##                "mongo_url" : "mongodb://localhost:27017/",
##		"analytics_db" : "tahoe_db",
##		"analytics_coll" : "instances"
##            }
##    
##    os.environ["_MONGO_URL"] = config.pop("mongo_url")
##    os.environ["_TAHOE_DB"] = config.pop("analytics_db", "tahoe_db")
##    os.environ["_TAHOE_COLL"] = config.pop("analytics_coll", "instances")
##    
##    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s:%(message)s') 
##
##    filt_cowrie()    


    

