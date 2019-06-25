# proc\parsescriipts\parse_cowrie.py
# This function depends on parse_common.py and cannot be run separately
# To run separately see parse_cowrie_test.py

def parse_cuckoo_report(line, tzname = 'UTC'):
    import json
    import pytz, datetime
    
    data = json.loads(line)

    local = pytz.timezone (tzname)
    naive = datetime.datetime.fromtimestamp(data['info']['started'])
    local_dt = local.localize(naive, is_dst=None)
    utc_dt = local_dt.astimezone(pytz.utc)

    time_final = utc_dt.isoformat()

    objects_val = {"0" :
                   {"type": "x-cuckoo-report",
                    "data" : data
                    }
                   }
    return [time_final, objects_val]

