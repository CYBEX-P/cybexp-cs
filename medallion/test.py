# Configure MongoDB for medalllion

from pymongo import MongoClient
import json

client = MongoClient()
db = client.discovery_database
coll = db.discovery_information

s1 = """{
     "title": "Qtest",
     "description": "Testing by Q",
     "contact": "qclass",
     "default": "http://localhost:5000/api2/",
     "api_roots": [
         "http://localhost:5000/api1/",
     ]
 }"""

d1 = json.loads(s1)
mid = coll.insert_one(d1)

coll = db.api_root_info

s2 = """{
    "title": "Default API Root",
    "description": "API Root Setup for Test",
    "versions": [
          "taxii-2.0"
    ],
    "max_content_length": 9765625,
    "_url": "http://localhost:5000/api1/",
    "_name": "api1"
}"""

d2 = json.loads(s2)
mid = coll.insert_one(d2)


from medallion.test.generic_initialize_mongodb import (add_api_root,
                                                       build_new_mongo_databases_and_collection,
                                                       connect_to_client)


