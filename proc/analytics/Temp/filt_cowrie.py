import sys
sys.path.append("..")
from common.loaddb import loaddb
from common.schema.stix2ext import *
import stix2
from pprint import pprint

db = loaddb('archive')
coll = db.events

_CYBEXP_ORGID = "63476b91-c478-42b6-a554-a32b02836dc0"

def cowrie_2_ip():
    global _CYBEXP_ORGID, coll
    filt_id = "filter--cd8b9c32-68ba-4403-82c5-df48e0fdde38"

    # Data
    r = coll.find({'objects.0.type':'x-unr-honeypot'})
    for jsd in r:
        std = stix.parse(jsd)
        import pdb
        pdb.set_trace()
    
    # Process
    time_final = din.first_observed
    orgid = _CYBEXP_ORGID

    objects_val = {
                    "0" : {
                      "type" : "ipvr-add4",
                      "value" : din.objects["0"]["data"]["src_ip"]
                    }
                  }
    od = observed_data(time_final, orgid, objects_val)
    
    
    
def observed_data(time_final, orgid, objects_val):  
    import uuid
    
    oid_val = "observed-data--" + str(uuid.uuid4())
    
    first_observed_val = time_final
    last_observed_val = first_observed_val
    number_observed_val = 1
    if created_by_ref_val = "identity--" + str(orgid)
    
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
