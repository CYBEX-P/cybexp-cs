import time, pdb, logging
from pymongo import MongoClient

URL = "mongodb://cybexp_user:CybExP_777@134.197.21.231:27017/?authSource=admin"
client = MongoClient(URL)
cache_db = client.cache_db
tahoe_db = client.tahoe_db
file_entries = cache_db.file_entries
instances = tahoe_db.instances

def main():
    while True:
        t = time.time()
        cache_count = file_entries.find({}).count()
        archive_count = instances.find({"itype":"raw"}).count()
        analytics_count = instances.find({"itype":"attribute"}).count()
        event_count = instances.find({"itype":"event"}).count()
        logging.info('{:.2f}\t{:d}\t{:d}\t{:d}\t{:d}'.format(
            t, cache_count, archive_count, analytics_count, event_count))
        time.sleep(5)

if __name__ == "__main__":
    logging.basicConfig(filename = 'metric.log', level=logging.DEBUG, format='%(message)s')
    main()
