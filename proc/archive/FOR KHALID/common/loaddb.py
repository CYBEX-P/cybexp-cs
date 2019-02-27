def loaddb(dbname):
    from pymongo import MongoClient
    URI = 'mongodb://cybexp_user:CybExP_777@134.197.21.231:27017/?authSource=admin'
    client = MongoClient(URI)
    if dbname == "report":
        db = client.report_db
    elif dbname == "cache":
        db = client.cache_db
    elif dbname == "archive":
        db = client.archive_db
    else:
        raise ValueError("Incorrect database name")
    return db
