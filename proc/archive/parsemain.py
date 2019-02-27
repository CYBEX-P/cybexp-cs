#parsemain.py
from common.schema.stix2ext import *
from parsescripts import *
import json
import stix2

def parsemain(lf, orgid, typtag, tzname):
    if isinstance(lf, bytes): lf = lf.decode() 
    lf = lf.split('\r\n')
    json_val = []
    for line in lf:
        if typtag =='cowrie':
            [time_final, objects_val] = parse_cowrie(line)
        if typtag == 'palo_alto_alert':
            [time_final, objects_val] = parse_palo_alto_alert(line, tzname)
        if typtag == 'iptables':
            [time_final, objects_val] = parse_iptables(line, tzname)
        if typtag == 'unr-honeypot':
            [time_final, objects_val] = parse_unr_honeypot(line, tzname)
        else:
            print("Unknown file type (typtag): " + typtag)
            continue
        observedDataRegKey = observed_data(time_final, orgid, objects_val)
        bundle = stix2.Bundle(objects = [observedDataRegKey])
        json_val.append(json.loads(observedDataRegKey.serialize()))       
    return bundle     

        
def observed_data(time_final, orgid, objects_val):  
    import uuid
    
    oid_val = "observed-data--" + str(uuid.uuid4())
    
    first_observed_val = time_final
    last_observed_val = first_observed_val
    number_observed_val = 1
    created_by_ref_val = "identity--" + str(orgid)
    
    observedDataRegKey = stix2.ObservedData(
        id = oid_val,
        first_observed = first_observed_val,
        last_observed = last_observed_val,
        number_observed = number_observed_val,
        created_by_ref = created_by_ref_val,
        objects = objects_val,
        allow_custom = True
    )

    return observedDataRegKey





