import pdb
from datetime import datetime as dt
from tahoe import NoBackend, Attribute, Object, Event, Session, parse

_PROJECTION = {"_id":0, "filters":0, "bad_data":0}
_VALID_ATT = ['ipv4', 'country_code3', 'longitude', 'region_name', 'city_name', 'region_code', 'country_name', 'latitude', 'timezone', 'continent_code', 'country_code2']

def decode_backend_config():
    mongo_url = os.getenv("_MONGO_URL")
    analytics_db = os.getenv("_ANALYTICS_DB", "tahoe_db")
    analytics_coll = os.getenv("_ANALYTICS_COLL", "instances")

    client = MongoClient(mongo_url)
    analytics_db = client.get_database(analytics_db)
    analytics_backend = MongoBackend(analytics_db)
    return analytics_backend

def filt_cowrie(backend=NoBackend()):
    filt_id = "filter--ad8c8d0c-0b25-4100-855e-06350a59750c"
    query = {"$and" : [{"raw_type" : "x-unr-honeypot"}, {"filters" : { "$ne": filt_id }}, { "data.eventid" : {"$exists":True}}]}
    if os.getenv("_MONGO_URL"): backend = decode_backend_config()
    cursor = backend.find(query, _PROJECTION)
    if cursor.count() == 0: return False
    for raw in cursor:
        eventid = raw["data"]["eventid"]
        if   eventid == "cowrie.client.version": j = ClientVersion(raw)
        elif eventid == "cowrie.command.failed": j = CommandInput(raw)
        elif eventid == "cowrie.command.input": j = CommandInput(raw)
        elif eventid == "cowrie.command.success": j = CommandInput(raw)
        elif eventid == "cowrie.direct-tcpip.data": j = DirectTcpIpData(raw) 
        elif eventid == "cowrie.direct-tcpip.request": j = DirectTcpIpRequest(raw)
        elif eventid == "cowrie.login.failed": j = LoginFailed(raw) 
        elif eventid == "cowrie.login.success": j = LoginSuccess(raw)
        
        elif eventid == "cowrie.session.closed":
            j = SessionClosed(raw)
        elif eventid == "cowrie.session.connect":
            j = SessionConnect(raw)
        elif eventid == "cowrie.session.file_download":
            j = SessionFileDownload(raw)
        else: continue
        
        backend.update_one( {"uuid" : raw["uuid"]}, {"$addToSet": {"filters": filt_id} })
        
            

        
##        elif i["data"]["eventid"] == "cowrie.session.file_download":
##            j = filt_cowrie_file_download(i, backend)
##        backend.update_one( {"uuid" : i["uuid"]}, {"$addToSet": {"filters": filt_id} })
    return True

class Cowrie():
    def __init__(self):
        self.orgid = self.raw["orgid"]
        timestamp = self.data["@timestamp"]
        timestamp = dt.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp()
        geoip_att = [Attribute(k, v) for k,v in self.data["geoip"].items() if k in  _VALID_ATT]

        attacker_ip = self.data["src_ip"]
        attacker_ip_att = Attribute('ipv4', attacker_ip)
        attacker_obj = Object('attacker', [attacker_ip_att] + geoip_att)
        self.objects.append(attacker_obj)
        
        e = Event(self.event_type, self.orgid, self.objects, timestamp)
        session = self.get_session()
        session.add_event(e)

    def get_session(self):
        sessionid = self.data['session']
        sessionid_att = Attribute('sessionid', sessionid)
        hostname = self.data['host']['name']
        hostname_att = Attribute('hostname', hostname)
        session_obj = Object('session_identifier', [hostname_att, sessionid_att])
        session = Session('cowrie_session', session_obj)
        return session
        

class ClientVersion(Cowrie):
    def __init__(self, raw):
        self.raw, self.data = raw, raw["data"]

        ssh_version = self.data["version"]
        if ssh_version[0] == "'": ssh_version = ssh_version.replace("'", "")
        ssh_version_att = Attribute('ssh_version', ssh_version)

        session = self.get_session()
        for event in session:
            if event["event_type"] == "ssh_login":
                event = parse(event_dict)
                for obj in event:
                    if obj["obj_type"] = "ssh":
                        obj = parse(obj)
                        obj.add_attribute(ssh_version_att)
                        return
                ssh_obj = Object('ssh', ssh_version_att)
                event.add_object(ssh_obj)

class CommandInput(Cowrie):
    def __init__(self, raw):
        self.raw, self.data, self.event_type = raw, raw["data"], 'shell_command'
        self.objects = [ Object('shell_command', Attribute('text', self.data["command"])) ]
        super().__init__()

class DirectTcpIp(Cowrie):
    def __init__(self):
        src_obj = Object('src', [Attribute('hostname', self.data['host']['name'])])
        dst_obj = Object('dst', [Attribute('url', self.data["dst_ip"])])
        dst_port_obj = Object('dst_port', [Attribute('port', self.data["dst_port"])])
        protocol_obj = Object('protocol', [Attribute('protocol', protocol)])

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
    login_obj = Object('login_credential', [Attribute('username', self.data["username"]),
                                                Attribute('password', self.data["password"])])
    self.objects += [login_obj]
    super().__init__()

class LoginFailed(Cowrie):
    def __init__(self, raw):
        self.raw, self.data, self.event_type = raw, raw["data"], 'ssh_login' 
        self.objects = [Object('login_success', [Attribute('boolean', success)])]
        super().__init__()

class LoginSuccess(Cowrie):
    def __init__(self, raw, backend):
        self.raw = raw
        self.data = self.raw["data"]
        self.backend = backend

        self.event_type = 'ssh_login'

        username = self.data["username"]
        password = self.data["password"]
        success = True

        username_att = Attribute('username', username)
        password_att = Attribute('password', password)
        success_att = Attribute('boolean', success)

        login_obj = Object('login_credential', [username_att, password_att])
        success_obj = Object('login_success', [success_att])

        self.objects = [login_obj, success_obj]
        
        super().__init__()






















                
class SessionConnect(Cowrie):
    def __init__(self, raw, backend):
        self.raw = raw
        self.data = self.raw["data"]
        self.backend = backend
        session = self.get_session()

        timestamp = self.data["@timestamp"]
        start_time = dt.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp()
        self.update = {"start_time" : start_time}
        
        session.update(self.update)
    
class SessionClosed(Cowrie):
    def __init__(self, raw, backend):
        self.raw = raw
        self.data = self.raw["data"]
        self.backend = backend
        session = self.get_session()

        duration = self.data["duration"]
        timestamp = self.data["@timestamp"]
        end_time = dt.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp()
        self.update = {"duration" : duration, "end_time" : end_time}
        
        session.update(self.update)
        


        


            

    


class SessionFileDownload(Cowrie):
    def __init__(self, raw, backend):
        self.raw = raw
        self.data = self.raw["data"]
        self.backend = backend

        self.event_type = 'file_download'

        url = self.data['url']
        filename = url.split('/')[-1]
        sha256 = self.data['shasum']

        url_att = Attribute('url', url)
        filename_att = Attribute('filename', filename)
        sha256_att = Attribute('sha256', sha256)

        url_obj = Object('url', [url_att])   
        file_obj = Object('file', [filename_att, sha256_att])

        self.objects = [url_obj, file_obj]
        super().__init__()


    

    


    

