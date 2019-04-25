if __name__ == "__main__":
    from views_comm import *
    from crypto import encrypt_file
else:
    from .views_comm import * # .views=views.py, views=this folder
    from .crypto import encrypt_file

from io import BytesIO
from datetime import datetime
import werkzeug

# Load Cache Database
ccoll = coll_or_fs('cache')
cfs = coll_or_fs('cache_fs')

# Post Events to API
ep = reqparse.RequestParser()
ep.add_argument('orgid', required=True)
ep.add_argument('file', location='files', required=True,
                type=werkzeug.datastructures.FileStorage)
ep.add_argument('typtag', required=True)
ep.add_argument('timezone', required=True)

def test():
    pass

class Event(Resource):
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
        try:
            info['fid'] = cfs.put(fenc, filename=f.filename)
            i = ccoll.insert_one(info)
        except pymongo.errors.ServerSelectionTimeoutError:
            return ({'message': 'Database down'}, 500)

        return ({'message': 'File Uploaded Succesfully'}, 201)
