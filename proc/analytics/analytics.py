# proc\analytics\analytics.py

from queue import Queue
import time, logging, copy, random, os, pdb

def exponential_backoff(n):
    s = min(3600, (2 ** n) + (random.randint(0, 1000) / 1000))
    time.sleep(s)

def infinite_worker(q):
    n_failed_attempts = 0
    while not q.empty():
        func = q.get()
        try:
            r = func()
            if not r:
                exponential_backoff(n_failed_attempts)
                n_failed_attempts += 1
            else:
                n_failed_attempts = 0

        except Exception as exception:
            logging.error("proc.analytics.infinite_worker: ", exc_info=True)
            exponential_backoff(n_failed_attempts)
            n_failed_attempts += 1
            
        q.task_done()
        q.put(func)

def analytics(config):
    try:
        os.environ["_MONGO_URL"] = config.pop("mongo_url")
        os.environ["_TAHOE_DB"] = config.pop("analytics_db", "tahoe_db")
        os.environ["_TAHOE_COLL"] = config.pop("analytics_coll", "instances")

        # Don't move the next statement to top, see github issue #5
        from filters import filt_misp, filt_cowrie  

        q = Queue()
        q.put(filt_misp)
        q.put(filt_cowrie)
        
        infinite_worker(q)

    except Exception: logging.error("proc.analytics.analytics: ", exc_info=True)

if __name__ == "__main__":
    analytics_config = { 
		"mongo_url" : "mongodb://cybexp_user:CybExP_777@134.197.21.231:27017/?authSource=admin",
		"analytics_db" : "tahoe_db",
		"analytics_coll" : "instances"
            }


    logging.basicConfig(filename = '../proc.log', level=logging.DEBUG, format='%(asctime)s %(levelname)s:%(message)s') # filename = '../proc.log',
 
    analytics(copy.deepcopy(analytics_config))

    

