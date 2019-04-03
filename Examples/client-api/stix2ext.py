from stix2 import CustomObservable, properties
from stix2 import IPv4Address
from stix2 import parse

@CustomObservable('palo-alto-alert', [
    ('category', properties.StringProperty(required=True)),
    ('severity', properties.StringProperty(required=True)),
    ('description', properties.StringProperty()),
    ('recv_type', properties.StringProperty()),
    ('src_ref', properties.ObjectReferenceProperty(valid_types=
        ['ipv4-addr', 'ipv6-addr', 'mac-addr', 'domain-name'])),
])
class PaloAltoAlert():
    pass


@CustomObservable('x-cowrie', [
    ('ver', properties.StringProperty(required=True)),
    ('eventid', properties.StringProperty(required=True)),
    ('msg', properties.StringProperty(required=True)),
    ('src_ref', properties.ObjectReferenceProperty(valid_types=
        ['ipv4-addr', 'ipv6-addr', 'mac-addr', 'domain-name'])),    
])
class Cowrie():
    pass

@CustomObservable('x-unr-honeypot', [])
class UnrHoneypot():
    pass

@CustomObservable('x-cuckoo-report', [])
class CuckooReport():
    pass
