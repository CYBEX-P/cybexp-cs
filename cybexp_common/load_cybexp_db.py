from pymongo import MongoClient
URI = 'mongodb://cybexp_user:CybExP_777@134.197.21.231:27017/?authSource=admin'
client = MongoClient(URI)
import gridfs

def coll_or_fs(collname):
    if collname == "report":      coll = client.archive_db.events
    elif collname == "cache":     coll = client.cache_db.file_entries
    elif collname == "archive":   coll = client.archive_db.events
    elif collname == "analytics": coll = client.archive_db.analytics
    elif collname == "cache_fs":  coll = gridfs.GridFS(client.cache_db)
    else:
        import pdb
        pdb.set_trace()
        raise ValueError("Incorrect Collection name")
    return coll


