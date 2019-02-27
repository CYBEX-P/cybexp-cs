from flask import Flask
from flask_restful import Resource, Api, reqparse
import werkzeug, os
from flask_pymongo import PyMongo
import pytz, gridfs, pymongo
from datetime import datetime

app = Flask(__name__)
app.config["MONGO_URI"] = "mongodb://cybexp_user:CybExP_777@134.197.21.231:27017/cache_db?authSource=admin"
app.config["MONGO_DBNAME"] = "cache_db"
mongo = PyMongo(app)
api = Api(app)

# File upload
f_parser = reqparse.RequestParser()
f_parser.add_argument('orgid', type=str, required=True)
f_parser.add_argument('file', type=werkzeug.datastructures.FileStorage,
                    location='files', required=True)
f_parser.add_argument('typtag', type=str, required=True)
f_parser.add_argument('timezone', type=str, required=True)

class FileUpload(Resource):
    decorators=[]
      
    def post(self):
        request = f_parser.parse_args()
        f = request['file']
        
        info = {}
        info['datetime'] = datetime.now(pytz.utc).isoformat()
        info['orgid'] = request['orgid']
        try: info['fid'] = mongo.save_file(f.filename, f)
        except pymongo.errors.ServerSelectionTimeoutError: return ({'message': 'Database down'}, 500)
        info['processed'] = False
        info['typtag'] = request['typtag']
        info['timezone'] = request['timezone']

        i = mongo.db.file_entries.insert_one(info)
        return ({'message': 'File Uploaded Succesfully'}, 201)

api.add_resource(FileUpload,'/api/v1.0/event')

if __name__ == '__main__':
    app.run(debug=True)
