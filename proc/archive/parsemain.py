#parsemain.py
import json
from parsescripts import *

def parsemain(lf, orgid, typtag, tzname):
    if isinstance(lf, bytes): lf = lf.decode() 
    lf = lf.split('\r\n')
    json_val = []
    for line in lf:
        if typtag == 'unr-honeypot':
            e = parse_unr_honeypot(line, orgid, tzname)
        else:
            print("Unknown file type (typtag): " + typtag)
            continue
       
    return json_val





