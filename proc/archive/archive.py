#proc.py

import sys
sys.path.append("..")

import time
import gridfs
from common.loaddb import loaddb
from common.dbam import put_data
from parsemain import parsemain


db = loaddb('cache')
coll = db.file_entries
fs = gridfs.GridFS(db)

while True:
    cursor = coll.find({'processed':False})
    if cursor.count() == 0:
        time.sleep(600)
        continue
    for e in cursor:
        upload_time = e['datetime']
        orgid = e['orgid']
        typtag = e['typtag']
        timezone = e['timezone']
        
        fid = e['fid']
        f = fs.get(fid)
        s = f.read()

        json_data = parsemain(s, orgid, typtag, timezone)
        for jd in json_data:
            i = put_data(jd)
        
        coll.update_one(e, {"$set":{"processed":True}})

        

