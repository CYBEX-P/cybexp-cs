# Load Cache Database
from pymongo import MongoClient
import gridfs
URI = 'mongodb://cybexp_user:CybExP_777@134.197.21.231:27017/?authSource=admin'
client = MongoClient(URI)

ccoll = client.cache_db.file_entries
cfs = gridfs.GridFS(client.cache_db)

r = ccoll.find({"processed":"true"})
for e in r:
    fid = e['fid']
    coll.delete(fid)
