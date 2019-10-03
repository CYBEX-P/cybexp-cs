import os

config = { 
            "mongo_url" : "mongodb://cybexp_user:CybExP_777@134.197.21.231:27017/?authSource=admin",
##            "mongo_url" : "mongodb://localhost:27017",
            "analytics_db" : "tahoe_db",
            "analytics_coll" : "instances"
        }
os.environ["_MONGO_URL"] = config.pop("mongo_url")
os.environ["_ANALYTICS_DB"] = config.pop("analytics_db", "tahoe_db")
os.environ["_ANALYTICS_COLL"] = config.pop("analytics_coll", "instances")
