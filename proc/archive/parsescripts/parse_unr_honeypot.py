# proc\parsescriipts\parse_cowrie.py
# This function depends on parse_common.py and cannot be run separately
# To run separately see parse_cowrie_test.py

def parse_unr_honeypot(line, tzname = 'UTC'):
    import json
    
    data = json.loads(line)

    try:
        time_final = data["timestamp"]
    except:
        return None, None

    objects_val = {"0" :
                   {"type": "x-unr-honeypot",
                    "data" : data
                    }
                   }
        
    return [time_final, objects_val]

