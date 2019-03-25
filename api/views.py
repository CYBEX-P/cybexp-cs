from flask_restful import Resource, reqparse
import werkzeug, pytz, pymongo
from datetime import datetime
from flask_jwt_extended import jwt_required
from run import mongo
from crypto import encrypt_file
import pdb
from io import BytesIO

# Post Events to API
event_parser = reqparse.RequestParser()
event_parser.add_argument('orgid', type=str, required=True)
event_parser.add_argument('file', type=werkzeug.datastructures.FileStorage,
                    location='files', required=True)
event_parser.add_argument('typtag', type=str, required=True)
event_parser.add_argument('timezone', type=str, required=True)

class Event(Resource):
    decorators=[]
    @jwt_required  
    def post(self):
        request = event_parser.parse_args()
        f = request['file']
        fenc = encrypt_file(f.read())
        fenc = BytesIO(fenc)
        
        info = {}
        info['datetime'] = datetime.now(pytz.utc).isoformat()
        info['orgid'] = request['orgid']
        try: info['fid'] = mongo.save_file(f.filename, fenc)
        except pymongo.errors.ServerSelectionTimeoutError: return ({'message': 'Database down'}, 500)
        
        info['processed'] = False
        info['typtag'] = request['typtag']
        info['timezone'] = request['timezone']

        i = mongo.db.file_entries.insert_one(info)
        return ({'message': 'File Uploaded Succesfully'}, 201)
