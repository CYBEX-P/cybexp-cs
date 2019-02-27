import sys, getopt

def main(argv):
    from common.schema.stix2ext import *
    from parsescripts import *
    import json

    lf = argv[1]
    orgid = argv[2]
    typtag = argv[3]
    tzname = argv[4]


    lf = lf.split('\r\n')
    json_val = []
    for line in lf:
        if typtag =='cowrie':
            [time_final, objects_val] = parse_cowrie(line)
        if typtag == 'palo_alto_alert':
            [time_final, objects_val] = parse_palo_alto_alert(line, tzname)
        if typtag == 'iptables':
            [time_final, objects_val] = parse_iptables(line, tzname)
        else:
            print("Unknown file type (typtag): " + typtag)
            continue
        observedDataRegKey = observed_data(time_final, orgid, objects_val)
        json_val = (json.loads(observedDataRegKey.serialize()))
        print(json_val)

def observed_data(time_final, orgid, objects_val):
    import stix2, uuid
    
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
        objects = objects_val
    )

    return observedDataRegKey

        
if __name__ == "__main__":
    main(sys.argv)

    
        
    





