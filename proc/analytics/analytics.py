# proc\analytics\analytics.py
from pymongo import MongoClient
from queue import Queue
import time, logging, copy, random, os

from tahoe import MongoBackend
from filters import filt_cowrie
import pdb

def exponential_backoff(n):
    s = min(3600, (2 ** n) + (random.randint(0, 1000) / 1000))
    time.sleep(s)

def infinite_worker(q):
    n = 0
    while not q.empty():
        print(n)
        items = q.get()
        func, args =  items[0], items[1:]
        try:
            r = func(*args)
            if not r:
                exponential_backoff(n)
                n += 1
            else:
                n = 0

        except Exception as exception:
            logging.error("proc.analytics.analytics: ", exc_info=True)
            exponential_backoff(n)
            n += 1
            
        q.task_done()
        q.put(items)

def analytics(config):
    try:
        os.environ["_MONGO_URL"] = config.pop("mongo_url")
        os.environ["_ANALYTICS_DB"] = config.pop("analytics_db", "tahoe_db")
        os.environ["_ANALYTICS_COLL"] = config.pop("analytics_coll", "instances")

        q = Queue()
        q.put([filt_cowrie])

        infinite_worker(q)

    except Exception: logging.error("proc.analytics.analytics: ", exc_info=True)

if __name__ == "__main__":
    analytics_config = { 
		"mongo_url" : "mongodb://cybexp_user:CybExP_777@134.197.21.231:27017/?authSource=admin",
		"analytics_db" : "tahoe_db",
		"analytics_coll" : "instances"
            }

    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s:%(message)s') # filename = '../proc.log',
 
    analytics(copy.deepcopy(analytics_config))

    

