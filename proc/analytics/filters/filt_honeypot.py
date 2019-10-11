import os, logging
from datetime import datetime as dt
from tahoe import get_backend, NoBackend, MongoBackend, Attribute, Object, Event, Session, parse
import pdb, pprint

_PROJECTION = {"_id":0, "filters":0, "bad_data":0}
_GEOIP_ATT = ['ipv4', 'country_code3', 'longitude', 'region_name', 'city_name', 'region_code', 'country_name', 'latitude', 'timezone', 'continent_code', 'country_code2']


def filt_honeypot(backend=NoBackend()):
    try:
        filt_id = "filter--8157fb19-4645-4e07-8771-34c5bffdeb1a"
               
        if os.getenv("_MONGO_URL"): backend = get_backend()
        assert isinstance(backend, MongoBackend)

        query = {"itype" : "raw", "sub_type" : "x-unr-honeypot", "data.sensor_domain":"wolfengineering-digitalocean",
                 "filters" : { "$ne": filt_id }, "_valid" : {"$ne" : False}}

        cursor = backend.find(query, _PROJECTION)
        assert cursor

        j = None
        for raw in cursor:
            # PFSense Firewall    
            if 'tags' in raw['data'] and 'PFSense' in raw['data']['tags']:
##                pprint.pprint(raw)
##                pdb.set_trace()
##                j = Pfsense(raw)
                continue

            # Cowrie Honeypot
            elif 'eventid' in raw['data']:
                eventid = raw['data']['eventid']
                if eventid[:6] != 'cowrie':
                    logging.warning("Unknown eventid: " + eventid)
                eventid = eventid[7:]
                
                f = {
                        'client.kex' : ClientKex,
                        'client.size' : ClientSize,
                        'client.var' : ClientVar,
                        'client.version' : ClientVersion,
                        'command.failed' : CommandInput,
                        'command.input' : CommandInput,
                        'command.success' : CommandInput,
                        'direct-tcpip.data' : DirectTcpIpData,
                        'direct-tcpip.request' : DirectTcpIpRequest,
                        'login.failed' : LoginFailed,
                        'login.success' : LoginSuccess,
                        'session.closed' : SessionClosed,
                        'session.connect' : SessionConnect,
                        'session.file_download' : SessionFileDownload,
                        'session.file_download.failed' : SessionFileDownload
                    }.get(eventid)

                if not f :
                    logging.warning("Unknown eventid: " + eventid + " in " + raw['uuid'])
                else:
                    j = f(raw)

            # Unknown data
            if not j:
                logging.warning("Unknown honeypot data: " + raw['uuid'])

        if cursor.retrieved == 0: return False
        
    except:
        logging.error("Error -- ", exc_info=True)
##        backend.update_one( {"uuid" : raw["uuid"]}, {"$set" : {"_valid" : False}})
        return False

    else:
        backend.update_one( {"uuid" : raw["uuid"]}, {"$addToSet": {"filters": filt_id} })
        return True


##class Pfsense():
##    def __init__(self, raw):
##        data, event_type = raw["data"], 'firewall_log'
##
##        b = NoBackend()
##
##        action = Attribute('fw_action', data['action'], backend=b)
##        direction = Attribute('packet_direction', data['data'], backend=b)
##        evtid = Attribute('pfsense_evtid', data['evtid'], backend=b)
##
##        # Layer 3
##        flags = Attribute('l3flags', data['flags'], backend=b)
##        ipid = Attribute('ipid', data['id'], backend=b)
##        
##        data_lenth = Attribute('data_length', data['data_length'], backend=b)
##        
##
##        iface = Attribute('iface', data['iface'], backend=b)
##
##        protocol = Attribute('protocol', data['proto'], backend=b)
##
##        srcip = Attribute('ipv4', data['src_ip'], backend=b)
##        srcport = Attribute('port', data['src_port'], backend=b)
##        src = Object('src', [srcip, srcport], backend=b)
##        
##        dstip = Attribute('ipv4', data['dest_ip'], backend=b)
##        dstport = Attribute('port', data['dest_port'], backend=b)
##        dst = Object('dst', [dstip, dstport], backend=b)
##        
##        pdb.set_trace()
        
##        src_obj = Object('src', [Attribute('hostname', self.data["src_ip"])])
##        dst_obj = Object('dst', [Attribute('ipv4', self.data["dest_ip"])])
####        src_port_obj = Object('src_port', 
####        dst_port_obj = Object('dst_port', [Attribute('port', self.data["dst_port"])])
####        protocol_obj = Object('protocol', [Attribute('protocol', "TCP")])
##        
##        
##        self.orgid = self.raw["orgid"]
##        timestamp = self.data["@timestamp"]
##        timestamp = dt.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp()
##        
##        geoip_attributes = [Attribute(k, v) for k,v in self.data["geoip"].items()]# if k in  _VALID_ATT]
##        geoip_obj = Object('geoip', geoip_attributes)
##        self.objects.append(geoip_obj)
##        
##        e = Event(self.event_type, self.orgid, self.objects, timestamp)


class Cowrie():
    def __init__(self):
        try:
            self.orgid = self.raw["orgid"]
            if 'sensor_domain' in self.data:
                self.orgid = {
                    "arfeducation-unr" : "identity--a35407b1-5aa5-4ce1-9936-9c03f5abc34e",
                    "piavinemedical-unr" : "identity--1c2a315e-cf61-4f6e-9c44-83486dee6db0",
                    "wolfengineering-digitalocean" : "identity--c0cdd619-ac3b-4d71-9bef-428ea681a89e"
                }.get(self.data['sensor_domain'])
            
            timestamp = self.data["@timestamp"]
            timestamp = dt.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp()

            if not hasattr(self, "mal_data"): self.mal_data = []
            
            attacker_ip_att = Attribute('ipv4', self.data["src_ip"], alias=['attacker_ip'])
            attacker_obj_data = [attacker_ip_att]

            if "geoip" in self.data["tags"]:
                geoip_att = [Attribute(k, v) for k,v in self.data["geoip"].items() if k in  _GEOIP_ATT]
                geoip_obj = Object('geoip', geoip_att)
                attacker_obj_data += [geoip_obj]
                self.mal_data += geoip_att
                
            attacker_obj = Object('attacker', attacker_obj_data)

            self.objects.append(attacker_obj)
            self.mal_data += [attacker_ip_att, attacker_obj]

            e = Event(self.event_type, self.objects, self.orgid, timestamp, malicious=True, mal_data = self.mal_data)

            session = self.get_session()
            session.add_event(e)

            raw = parse(self.raw)
            ref_uuid_list = e.related_uuid() + [session.uuid]
            raw.update_ref(ref_uuid_list)

        except:
            print("Error Not parsed -- delete me")

    def get_session(self):
        sessionid = self.data['session']
        sessionid_att = Attribute('sessionid', sessionid, alias=['x_cowrie_sessionid'])
        hostname = self.data['host']['name']
        hostname_att = Attribute('hostname', hostname)
        session = Session('cowrie_session', [sessionid_att, hostname_att])
        return session


class ClientKex(Cowrie):
    def __init__(self, raw):
        self.raw, self.data, self.event_type = raw, raw["data"], 'ssh_key_exchange'

        encCS = [e.split('@')[0] for e in self.data["encCS"]]
        enc_att = [Attribute('encr_algo', enc_algo) for enc_algo in encCS]
        enc_obj = Object('encr_algo_set', enc_att)

        compCS = self.data["compCS"]
        if compCS: comp_att = [Attribute('comp_algo', comp_algo) for comp_algo in compCS]
        else: comp_att = [Attribute('comp_algo', 'none')]
        comp_obj = Object('comp_algo_set', comp_att)

        kexAlgs = [e.split('@')[0] for e in self.data["kexAlgs"]]
        kex_algo_att = [Attribute('kex_algo', kex_algo) for kex_algo in kexAlgs]
        kex_obj = Object('kex_algo_set', kex_algo_att)

        keyAlgs = [e.split('@')[0] for e in self.data["keyAlgs"]]
        pub_key_algo_att = [Attribute('pub_key_algo', pub_key_algo) for pub_key_algo in keyAlgs]
        pub_key_obj = Object('pub_key_algo_set', pub_key_algo_att)

        macCS = [e.split('@')[0] for e in self.data["macCS"]]
        mac_att = [Attribute('mac_algo', mac_algo) for mac_algo in macCS]
        mac_obj = Object('mac_algo_set', mac_att)

        hash_obj = Object('hash', Attribute('hash', self.data['hassh']))

        self.objects = [enc_obj, comp_obj, kex_obj, pub_key_obj, mac_obj, hash_obj]
        super().__init__()

class ClientSize(Cowrie):
    def __init__(self, raw):
        self.raw, self.data, self.event_type = raw, raw["data"], 'ssh_client_size'
        height_att = Attribute('height', self.data["height"])
        width_att = Attribute('width', self.data["width"])
        ssh_obj = Object('ssh_client_size', [height_att, width_att])
        self.objects = [ssh_obj]
        super().__init__()

class ClientVar(Cowrie):
    def __init__(self, raw):
        self.raw, self.data, self.event_type = raw, raw["data"], 'ssh_client_env'
        env_att = Attribute('text', self.data["msg"])
        ssh_obj = Object('ssh_client_env', [env_att])
        self.objects = [ssh_obj]
        super().__init__()

class ClientVersion(Cowrie):
    def __init__(self, raw):
        self.raw, self.data, self.event_type = raw, raw["data"], 'ssh_version'
        ssh_version = self.data["version"]
        if ssh_version[0] == "'": ssh_version = ssh_version.replace("'", "")
        ssh_version_att = Attribute('ssh_version', ssh_version)
        ssh_obj = Object('ssh_version', ssh_version_att)
        self.objects = [ssh_obj]
        super().__init__()


class CommandInput(Cowrie):
    def __init__(self, raw, objects=[]):
        self.raw, self.data, self.event_type = raw, raw["data"], 'shell_command'
        self.objects = objects + [ Object('shell_command', Attribute('text', self.data["command"])) ]
        super().__init__()

class CommandSuccess(CommandInput):
    def __init__(self, raw):
        objects = [Object('success', [Attribute('boolean', True)])]
        super().__init__(raw, objects)

class CommandFailed(CommandInput):
    def __init__(self, raw):
        objects = [Object('success', [Attribute('boolean', False)])]
        super().__init__(raw, objects)

class DirectTcpIp(Cowrie):
    def __init__(self):
        src_obj = Object('src', [Attribute('hostname', self.data['host']['name'])])
        dst_obj = Object('dst', [Attribute('url', self.data["dst_ip"])])
        dst_port_obj = Object('dst_port', [Attribute('port', self.data["dst_port"])])
        protocol_obj = Object('protocol', [Attribute('protocol', "TCP")])

        self.objects += [src_obj, dst_obj, dst_port_obj, protocol_obj]
        super().__init__()

class DirectTcpIpData(DirectTcpIp):
    def __init__(self, raw):
        self.raw, self.data, self.event_type = raw, raw["data"], 'network_traffic'
        data_obj = Object('data', Attribute('data', self.data["data"]))
        self.objects = [data_obj]
        super().__init__()

class DirectTcpIpRequest(DirectTcpIp):
    def __init__(self, raw):
        self.raw, self.data, self.event_type = raw, raw["data"], 'network_traffic'
        src_port_obj = Object('src_port', [Attribute('port', self.data["src_port"])])
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
        self.objects = [Object('success', [Attribute('boolean', False)])]
        super().__init__()

class LoginSuccess(Login):
    def __init__(self, raw):
        self.raw, self.data, self.event_type = raw, raw["data"], 'ssh_login' 
        self.objects = [Object('success', [Attribute('boolean', True)])]
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
        self.objects = [Object('url', [Attribute('url', self.data['url'])])]
        filename_att = Attribute('filename', self.data['url'].split('/')[-1])
        try: sha256_att = Attribute('sha256', self.data['shasum'])
        except: self.objects += [Object('file', [filename_att]), Object('success', [Attribute('boolean', False)])]
        else: self.objects += [Object('file', [filename_att, sha256_att])]
        super().__init__()


   
if __name__ == "__main__":
    config = { 
		"mongo_url" : "mongodb://cybexp_user:CybExP_777@134.197.21.231:27017/?authSource=admin",
##                "mongo_url" : "mongodb://localhost:27017/",
		"analytics_db" : "tahoe_db",
		"analytics_coll" : "instances"
            }
    
    os.environ["_MONGO_URL"] = config.pop("mongo_url")
    os.environ["_TAHOE_DB"] = config.pop("analytics_db", "tahoe_db")
    os.environ["_TAHOE_COLL"] = config.pop("analytics_coll", "instances")
    
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s - File: %(filename)s - Function: %(funcName)s - Line: %(lineno)s -- %(message)s') 

    filt_honeypot()    

