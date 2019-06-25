def parse_iptables(line, tzname):
    """
    input = One line of iptables log file (network packet data)
    output = corresponding stix 2.0 object in python
    The stix.20 object suitable for network logs is ObservedData
    """
    
    from dateutil.parser import parse
    import arrow
    import stix2
    import uuid

    flags = {"URG": 32, "ACK":16, "PSH":8, "RST": 4, "SYN":2, "FIN":1}
    
    line = line.split()
    oid_val = "observed-data--" + str(uuid.uuid4())
    time_final = str(arrow.get(parse(" ".join(line[0:3]))))

    objects_val = {"0":{},"1":{},"2":{}}

    src_ref_val = next((s[4:] for s in line if "SRC=" in s), None)
    if src_ref_val == None: return None
    dst_ref_val = next((s[4:] for s in line if "DST=" in s), None)
    protocols_val = next((s[6:] for s in line if "PROTO=" in s), None)
    src_port_val = next((s[4:] for s in line if "SPT=" in s), None)
    dst_port_val = next((s[4:] for s in line if "DPT=" in s), None)
    src_byte_count_val = next((s[4:] for s in line if "LEN=" in s), None)
    
    objects_val["0"]["type"] = "ipv4-addr"
    objects_val["0"]["value"] = src_ref_val
    objects_val["1"]["type"] = "ipv4-addr"
    objects_val["1"]["value"] = dst_ref_val
    objects_val["2"]["type"] = "network-traffic"
    objects_val["2"]["src_ref"] = "0"
    objects_val["2"]["dst_ref"] = "1"
    objects_val["2"]["protocols"] = [protocols_val]

    if src_port_val: objects_val["2"]["src_port"] = int(src_port_val)
    if dst_port_val: objects_val["2"]["dst_port"] = int(dst_port_val)
    objects_val["2"]["src_byte_count"] = src_byte_count_val

    objects_val["2"]["ipfix"] ={}

    if protocols_val == "TCP":
        src_flags_hex_val = 0
        for f in flags:
            if f in line: src_flags_hex_val += flags[f]
        src_flags_hex_val = format(src_flags_hex_val, "02x")
        objects_val["2"]["extensions"] = {
            "tcp-ext":{"src_flags_hex":src_flags_hex_val}}
        
        tcpUrgentPointer_val = next((s[5:] for s in line if "URGP=" in s), None)
        tcpUrgentPointer_val = int(tcpUrgentPointer_val)
        objects_val["2"]["ipfix"]["tcpUrgentPointer"] = tcpUrgentPointer_val

        tcpWindowSize_val = next((s[7:] for s in line if "WINDOW=" in s), None)
        tcpWindowSize_val = int(tcpWindowSize_val)
        objects_val["2"]["ipfix"]["tcpWindowSize"] = tcpWindowSize_val
        
    elif protocols_val == "ICMP":
        icmp_type_hex_val = next((s[5:] for s in line if "TYPE=" in s), None)
        icmp_code_hex_val = next((s[5:] for s in line if "CODE=" in s), None)
        if (icmp_type_hex_val != None) & (icmp_code_hex_val != None): 
            icmp_type_hex_val = format(int(icmp_type_hex_val), "02x")
            icmp_code_hex_val = format(int(icmp_code_hex_val), "02x")
            objects_val["2"]["extensions"] = {
                "icmp-ext":{"icmp_type_hex":icmp_type_hex_val,
                            "icmp_code_hex":icmp_code_hex_val}}

    if "INBOUND" in line:
        flowDirection_val = 0           # Ingress
    else: flowDirection_val = 1         # Egress
    objects_val["2"]["ipfix"]["flowDirection"] = flowDirection_val

    ipClassOfService_val = next((s[4:] for s in line if "TOS=" in s), None)
    ipClassOfService_val = int(ipClassOfService_val, 16)    # IP TOS
    objects_val["2"]["ipfix"]["ipClassOfService"] = ipClassOfService_val
    
    ipTTL_val = next((s[4:] for s in line if "TTL=" in s), None)
    ipTTL_val = int(ipTTL_val)
    objects_val["2"]["ipfix"]["ipTTL"] = ipTTL_val

    return [time_final, objects_val]
    



