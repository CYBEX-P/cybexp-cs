def parse_palo_alto_alert(line, tzname):
    from datetime import datetime
    import pytz, ast
    
    data = ast.literal_eval(line)
    
    time = data['time']
    time_naive_local = datetime.strptime(time, '%Y/%m/%d %H:%M:%S')
    tz = pytz.timezone(tzname)
    time_aware_local = tz.localize(time_naive_local)
    time_aware_utc = time_aware_local.astimezone(pytz.utc)
    time_final = time_aware_utc.isoformat()
    

    objects_val = {"0":{},"1":{}}
   
    objects_val["0"]["type"] = "ipv4-addr"
    objects_val["0"]["value"] = data["sip"]
    
    objects_val["1"]["type"] = "x-palo-alto-alert"
    objects_val["1"]["ver"] = "0.1"
    objects_val["1"]["category"] = data["category"]
    objects_val["1"]["severity"] = data["severity"]
    objects_val["1"]["description"] = data["description"]
    objects_val["1"]["recv_type"] = data["type"]
    objects_val["1"]["src_ref"] = "0"
    
    return [time_final, objects_val]


##def parse_palo_alto_alert(line, orgid, tzname):
##    from datetime import datetime
##    import pytz, ast
##    
##    data = ast.literal_eval(line)
##    
##    time = data['time']
##    time_naive_local = datetime.strptime(time, '%Y/%m/%d %H:%M:%S')
##    tz = pytz.timezone(tzname)
##    time_aware_local = tz.localize(time_naive_local)
##    time_aware_utc = time_aware_local.astimezone(pytz.utc)
##    time_final = time_aware_utc.isoformat()
##    
##
##    objects_val = {"0":{},"1":{}}
##   
##    objects_val["0"]["type"] = "ipv4-addr"
##    objects_val["0"]["value"] = data["sip"]
##    objects_val["1"]["type"] = "palo-alto-alert"
##    objects_val["1"]["category"] = data["category"]
##    objects_val["1"]["severity"] = data["severity"]
##    objects_val["1"]["description"] = data["description"]
##    objects_val["1"]["recv_type"] = data["type"]
##    objects_val["1"]["src_ref"] = "0"
##    
##    return observed_data(time_final, orgid, objects_val)
