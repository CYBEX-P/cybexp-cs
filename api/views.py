from flask_restful import Resource, reqparse
import werkzeug, pytz, pymongo
from datetime import datetime
from flask_jwt_extended import jwt_required
from run import mongo
from crypto import encrypt_file
import pdb
from io import BytesIO
import json
from bson import json_util
from flask import jsonify

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

related_parser = reqparse.RequestParser()
related_parser.add_argument('ipv4-addr', type=str)


from pymongo import MongoClient
rep_URI = 'mongodb://cybexp_user:CybExP_777@134.197.21.231:27017/?authSource=admin'
rep_client = MongoClient(rep_URI)
rep_db = rep_client.archive_db
rep_coll = rep_db.events

def get_ipv4_related(ipv4_addr):
    result = {}
    
    # Find matching ipv4-addr object
    query = {
        "$and" : [
            {"objects.0.value" : ipv4_addr},
            {"objects.0.type":"ipv4-addr"}
        ]
    }
    projection = {"_id":0, "filters":0, "bad_data":0}
    ipobj = rep_coll.find_one(query, projection)
    if not ipobj: return None
    result["0"] = ipobj

    # Find all relations
    query = {
        "$and" : [
            {"type" : "relationship"},
            {
                "$or" : [
                    {"source_ref" : ipobj["id"]},
                    {"target_ref" : ipobj["id"]}
                ]
            },
            {"relationship_type" : {"$ne" : "filtered-from"}}
        ]
    }
    projection = {"_id":0, "filters":0, "baddata":0}
    all_rels = rep_coll.find(query, projection)

    # Find all related objects
    count = 1
    for rel in all_rels:
        result[str(count)] = rel
        count += 1
        if rel["source_ref"] == ipobj["id"] :
            objid = rel["target_ref"]
        else: objid = rel["source_ref"]
        query = {"id" : objid}
        projection = {"_id":0, "filters":0, "badrdata":0}
        rel_obj = rep_coll.find_one(query, projection)
        result[str(count)] = rel_obj
        count += 1
        
    return result

class Related(Resource):
    decorators = []
      
##    @jwt_required
    def post(self):
        response = {}
        req = related_parser.parse_args()
        if 'ipv4-addr' in req.keys():
            ipv4_addr = req['ipv4-addr']
            r = get_ipv4_related(ipv4_addr)
            if not r:
                return ({'message': 'IP Address Not Found'}, 200)

        return (r, 200)
        
