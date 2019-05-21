# proc\parsescriipts\parse_cowrie.py
# This function depends on parse_common.py and cannot be run separately
# To run separately see parse_cowrie_test.py

def parse_misp_event(line, tzname = 'UTC'):
    import json, datetime, pytz
    
    data = json.loads(line)

    try:
        dt = data['Event']['publish_timestamp']
    except:
        return None, None
    dt = datetime.datetime.utcfromtimestamp(int(dt))
    time_final = pytz.utc.localize(dt).isoformat()

    objects_val = {"0" :
                   {"type": "x-misp-event",
                    "data" : data
                    }
                   }
        
    return [time_final, objects_val]


