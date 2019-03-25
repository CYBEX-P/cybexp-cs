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
        elif typtag == 'palo_alto_alert':
            [time_final, objects_val] = parse_palo_alto_alert(line, tzname)
        elif typtag == 'iptables':
            [time_final, objects_val] = parse_iptables(line, tzname)
        elif typtag == 'unr-honeypot':
            [time_final, objects_val] = parse_unr_honeypot(line, tzname)
        elif typtag == 'cuckoo-report':
            [time_final, objects_val] = parse_cuckoo_report(line, tzname)
        else:
            print("Unknown file type (typtag): " + typtag)
            import pdb
            pdb.set_trace()
            continue
        try:
            observedDataRegKey = observed_data(time_final, orgid, objects_val)
        except:
            pass
##        bundle = stix2.Bundle(objects = [observedDataRegKey])
        json_val.append(json.loads(observedDataRegKey.serialize()))       
    return json_val 

        
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





