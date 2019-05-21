# proc\parsescriipts\parse_cowrie.py
# This function depends on parse_common.py and cannot be run separately
# To run separately see parse_cowrie_test.py

def parse_cowrie(line, tzname = 'UTC'):
    import json
    
    data = json.loads(line)

    try:
        time_final = data["timestamp"]
    except:
        return None, None

    objects_val = {"0":{},"1":{}}
   
    objects_val["0"]["type"] = "ipv4-addr"
    objects_val["0"]["value"] = data["src_ip"]
    
    objects_val["1"]["type"] = "x-cowrie"
    objects_val["1"]["ver"] = "0.1"
    objects_val["1"]["eventid"] = data["eventid"]
    objects_val["1"]["msg"] = data["msg"]
    objects_val["1"]["src_ref"] = "0"
        
    return [time_final, objects_val]
