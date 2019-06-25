from jsonschema import Draft7Validator
from collections import OrderedDict
from uuid import uuid4
import json

class Instance():
    def __init__(self, _nid, uuid, _raw_ref, _valid):
        
        if not uuid: uuid = self.itype + '--' + str(uuid4())

        if _nid: self._nid = _nid
        self.uuid = uuid
        self._raw_ref = _raw_ref
        self._valid = _valid

        self.validate()

    def __str__(self):
        return self.json()

    def validate(self):
        instance = vars(self)
##        schema_name = "schema\\" + self.itype + ".json"
##        with open(schema_name) as f:
##            schema = json.load(f)
        schema = json.loads(eval(self.itype + "_schema"))
        d = Draft7Validator(schema)
        d.validate(instance)

    def json(self):
        instance = json.dumps(self.__dict__)
        return instance
    
    def serialize():
        pass

    def bundle():
        pass
                
    
class Event(Instance):
    def __init__(self, event_type, objects, timestamp, malicious=False, _session_ref=[],
                 _nid=None, uuid=None, _raw_ref=[], _valid=True):

        if type(objects) is not list: objects = [objects]

        self.itype = 'event'
        self.event_type = event_type
        self.objects = []
        for o in objects:
            self.objects.append(o.data())    
        self.timestamp = timestamp
        self.malicious = malicious
        self._session_ref = _session_ref
        
        super().__init__(_nid, uuid, _raw_ref, _valid)        



class Object(Instance):
    def __init__(self, obj_type, attributes, _event_ref=[],
                 _nid=None, uuid=None, _raw_ref=[], _valid=True):

        if type(attributes) is not list: attributes = [attributes]

        self.itype = 'object'
        self.obj_type = obj_type
        self.attributes = {}
        for att in attributes:
            self.attributes[att.att_type] = att.value
        self._event_ref = _event_ref
        
        super().__init__(_nid, uuid, _raw_ref, _valid)

    def add_event_ref(uuid):
        self._event_ref.append(uuid)

    def data(self):
        d = {self.obj_type : {} }
        for k,v in self.attributes.items():
            d[self.obj_type][k] = v

        return d

class Attribute(Instance):
    def __init__(self, att_type, value, _obj_ref=[],
                 _nid=None, uuid=None, _raw_ref=[], _valid=True):

        self.itype = 'attribute'
        self.att_type = att_type
        self.value = value
        self._obj_ref = _obj_ref

        super().__init__(_nid, uuid, _raw_ref, _valid)


attribute_schema = r"""{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "title": "attribute_core",
  "description" : "Validate core structure of an attribute.",
  "required": ["itype", "uuid", "att_type", "value"],
  "properties": {
    "itype": {"const" : "attribute"},
    "_nid": { "type": "integer", "minimum" : 1, "maximum" : 9223372036854775806 },
    "uuid": { "type": "string", "pattern" : "^attribute--[0-9a-fA-F]{8}\\-[0-9a-fA-F]{4}\\-[0-9a-fA-F]{4}\\-[89abAB][0-9a-fA-F]{3}\\-[0-9a-fA-F]{12}$"},
	"_obj_ref" : { "type" : "array", "items" : {  "type": "integer"} },
	"_raw_ref" : { "type" : "array", "items" : {  "type": "integer"} },
	"_valid": {"type": "boolean"},
	"att_type": { "enum" : ["asn", "btc", "text", "domain", "filename", "hash", "hostname", "ipv4", "ipv6", "md5", "network", "port", "sha1", "sha224", "sha256", "time", "timeiso","timestamp", "timezone", "uri", "url"]},
	"value": {"oneOf" : [{"type": "integer"}, {"type": "string"}]}
  },
  "additionalProperties": false,
  
  "allOf" : [
  
  {"if":{"properties":{"att_type":{"const":     "asn"    }}}, "then": {"properties": { "value": { "type": "integer", "minimum": 1, "maximum": 65535 }}}},
  
  {"if":{"properties":{"att_type":{"const":     "btc"    }}}, "then": {"properties": { "value": { "type": "string", "pattern": "^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$" }}}},
  
  {"if":{"properties":{"att_type":{"const":   "text"  }}}, "then": {"properties": { "value": { "type": "string", "maxLength": 1000 }}}},
  
  {"if":{"properties":{"att_type":{"const":   "domain"   }}}, "then": {"properties": { "value": { "type": "string", "pattern": "^(?!:\/\/)([a-zA-Z0-9-_]+\\.)*[a-zA-Z0-9][a-zA-Z0-9-_]+\\.[a-zA-Z]{2,11}?$" }}}},
  
  {"if":{"properties":{"att_type":{"const":  "filename"  }}}, "then": {"properties": { "value": { "type": "string", "pattern": "^[\\w\\-. ]+$" }}}},
   
  {"if":{"properties":{"att_type":{"const":    "hash"    }}}, "then": {"properties": { "value": { "type": "string", "pattern": "^[a-fA-F0-9]+$" }}}},
  
  {"if":{"properties":{"att_type":{"const":  "hostname"  }}}, "then": {"properties": { "value": { "type": "string", "pattern": "^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\\-]*[a-zA-Z0-9])\\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\\-]*[A-Za-z0-9])$" }}}},
  
  {"if":{"properties":{"att_type":{"const":    "ipv4"    }}}, "then": {"properties": { "value": { "type": "string", "pattern": "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$" }}}},
  
  {"if":{"properties":{"att_type":{"const":    "ipv6"    }}}, "then": {"properties": { "value": { "type": "string", "pattern": "^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$" }}}},
  
  {"if":{"properties":{"att_type":{"const":     "md5"    }}}, "then": {"properties": { "value": { "type": "string", "pattern": "^[a-fA-F\\d]{32}$" }}}},
  
  {"if":{"properties":{"att_type":{"const":   "network"  }}}, "then": {"properties": { "value": { "type": "string", "pattern": "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/(3[0-2]|[1-2][0-9]|[0-9]))$" }}}},
  
  {"if":{"properties":{"att_type":{"const":    "port"    }}}, "then": {"properties": { "value": { "type": "integer", "minimum": 1, "maximum": 65535 }}}},
  
  {"if":{"properties":{"att_type":{"const":    "sha1"    }}}, "then": {"properties": { "value": { "type": "string", "pattern": "^[0-9A-Fa-f]{5,40}$" }}}},
  
  {"if":{"properties":{"att_type":{"const":   "sha256"   }}}, "then": {"properties": { "value": { "type": "string", "pattern": "^[A-Fa-f0-9]{64}$" }}}},
  
  {"if":{"properties":{"att_type":{"const":  "timestamp" }}}, "then": {"properties": { "value": { "type": "number", "minimum": 0}}}},

  {"if":{"properties":{"att_type":{"const":     "url"    }}}, "then": {"properties": { "value": { "type": "string"}}}}

  
  ]
}
"""

event_schema = r"""{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "title": "event_core",
  "description" : "Validate core structure of an event.",
  "required": ["itype", "uuid", "event_type", "objects"],
  "properties": {
	"itype": {"const" : "event"},
    "_nid": { "type": "integer", "minimum" : 1, "maximum" : 9223372036854775806 },
    "uuid": { "type": "string", "pattern" : "^event--[0-9a-fA-F]{8}\\-[0-9a-fA-F]{4}\\-[0-9a-fA-F]{4}\\-[89abAB][0-9a-fA-F]{3}\\-[0-9a-fA-F]{12}$" },
    "orgid": { "type": "string"}, 
	"timestamp": { "type": "number", "minimum": 0 },
	"_session_ref" : { "type" : "array", "items" : {  "type": "integer"} },
	"_raw_ref" : { "type" : "array", "items" : {  "type": "integer"} },
	"_valid": {"type": "boolean"},
	"event_type": { "enum" : ["firewall_log", "email", "ssh_login", "payload_delivery", "sighting", "cowrie", "file_download"]},
	"objects": { "type" : "array"},
	"malicious" : {"type" : "boolean"}
  },
  "additionalProperties": false
}
"""

object_schema = r'''{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "title": "object_core",
  "description" : "Validate core structure of an object.",
  "required": ["itype", "uuid", "obj_type", "attributes"],
  "properties": {
    "itype": {"const" : "object"},
    "_nid": { "type": "integer", "minimum" : 1, "maximum" : 9223372036854775806 },
    "uuid": { "type": "string", "pattern" : "^object--[0-9a-fA-F]{8}\\-[0-9a-fA-F]{4}\\-[0-9a-fA-F]{4}\\-[89abAB][0-9a-fA-F]{3}\\-[0-9a-fA-F]{12}$" },
	"_event_ref" : { "type" : "array", "items" : {  "type": "integer"} },
	"_raw_ref" : { "type" : "array", "items" : {  "type": "integer"} },
	"_valid": {"type": "boolean"},
	"obj_type": { "enum" : ["autonomous-system", "btc", "comment", "domain", "file", "hash", "host", "ip", "network", "port", "time", "uri", "url"]},
	"attributes": { "type" : "object"}
  },
  "additionalProperties": false
}'''

