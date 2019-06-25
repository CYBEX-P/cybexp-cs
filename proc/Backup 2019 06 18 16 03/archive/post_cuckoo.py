#post_cuckoo.py
import os
import sys
sys.path.append("..")

import time, json
import gridfs
from common.loaddb import loaddb
from common.dbam import put_data
from parsemain import parsemain
import os


directory_in_str = "D:\\Data\\cuckoo_reports\\report"

directory = os.fsencode(directory_in_str)
directory_mv = os.fsencode("D:\\Data\\cuckoo_reports\\report\\Processed")

for file in os.listdir(directory):
     suc = False
     filename = os.fsdecode(file)
     if filename.endswith(".json"): 
         fn = (os.path.join(directory.decode(), filename))
         fnmv = (os.path.join(directory_mv.decode(), filename))
         with open(fn) as f:
               s = f.read()
               orgid = "f27df111-ca31-4700-99d4-2635b6c37851"
               typtag = "cuckoo-report"
               timezone = "US/Pacific"
               try:
                    json_data = parsemain(s, orgid, typtag, timezone)
                    for jd in json_data:
                         i = put_data(jd)
                    suc = True
               except:
                    print(filename)
         if suc:
              os.rename(fn, fnmv)
              

     else:
         continue
