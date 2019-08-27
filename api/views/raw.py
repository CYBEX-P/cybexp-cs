if __name__ == "__main__":
    from views_comm import *
    from crypto import encrypt_file
else:
    from .views_comm import * 
    from .crypto import encrypt_file

from io import BytesIO
from datetime import datetime
import werkzeug

# Load Cache Database
from pymongo import MongoClient
import gridfs
URI = 'mongodb://cybexp_user:CybExP_777@134.197.21.231:27017/?authSource=admin'
client = MongoClient(URI)

ccoll = client.cache_db.file_entries
cfs = gridfs.GridFS(client.cache_db)

# Post Events to API
ep = reqparse.RequestParser()
ep.add_argument('orgid', required=True)
ep.add_argument('file', location='files', required=True, type=werkzeug.datastructures.FileStorage)
ep.add_argument('typtag', required=True)
ep.add_argument('timezone', required=True)
##ep.add_argument('name', required=True)

class Raw(Resource):
    decorators=[]
    @jwt_required  
    def post(self):
        request = ep.parse_args()
        f = request['file']
        fenc = encrypt_file(f.read())
        fenc = BytesIO(fenc)
        
        info = {}
        info['datetime'] = datetime.now(pytz.utc).isoformat()
        info['orgid'] = request['orgid']
        info['processed'] = False
        info['typtag'] = request['typtag']
        info['timezone'] = request['timezone']
##        info['name'] = request['name']
        try:
            info['fid'] = cfs.put(fenc, filename=f.filename)
            i = ccoll.insert_one(info)
        except pymongo.errors.ServerSelectionTimeoutError:
            return ({'message': 'Database down'}, 500)

        return ({'message': 'File Uploaded Succesfully'}, 201)
