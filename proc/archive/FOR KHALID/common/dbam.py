from loaddb import loaddb

db = loaddb('archive')
coll = db.events

def get_data(query):
    None
    
def put_data(json_data):
    i = coll.insert_one(json_data)
    return i
    
