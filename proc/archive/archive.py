import io, time, gridfs, logging, json, copy, pdb, random, time, threading, multiprocessing
from pymongo import MongoClient
from pymongo.errors import CursorNotFound
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from tahoe import Raw, MongoBackend, NoBackend

def decode_archive_config(config):
    mongo_url = config.pop("mongo_url")
    cache_db = config.pop("cache_db", "cache_db")
    cache_coll = config.pop("cache_coll", "file_entries")
    archive_db = config.pop("archive_db", "tahoe_db")
    archive_coll = config.pop("archive_coll", "instances")
    private_key_file_path = config.pop("private_key", "priv.pem")

    client = MongoClient(mongo_url)
    cache_db = client.get_database(cache_db)
    archive_db = client.get_database(archive_db)
    cache_coll = cache_db.get_collection(cache_coll)
    archive_backend = MongoBackend(archive_db)
    fs = gridfs.GridFS(cache_db)

    return cache_coll, archive_backend, fs, private_key_file_path

def decrypt_file(file_in, fpriv_name="priv.pem"):
    if isinstance(file_in, bytes): file_in = io.BytesIO(file_in)
    private_key = RSA.import_key(open(fpriv_name).read())
    enc_session_key, nonce, tag, ciphertext = [ file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]

    # Decrypt the session key with the private RSA key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    # Decrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)

    return data.decode("utf-8")

def parsemain(data, orgid, typtag, timezone, backend):
    raw_type = {'unr-honeypot' : 'x-unr-honeypot', 'misp-api':'x-misp-event'}.get(typtag)
    raw = Raw(raw_type, data, 'identity--'+orgid, timezone=timezone, backend=backend)
    return raw

def exponential_backoff(n):
    s = max(3600, (2 ** n) + (random.randint(0, 1000) / 1000))
    time.sleep(s)



running = 0

def archive_one(event, config):
    cache_coll, archive_backend, fs, private_key_file_path =  decode_archive_config(config)
    try: 
        upload_time = event['datetime']
        orgid = event['orgid']
        typtag = event['typtag']
        timezone = event['timezone']
        fid = event['fid']
        f = fs.get(fid)

        data = str(decrypt_file(f, private_key_file_path))
        instance = parsemain(data, orgid, typtag, timezone, archive_backend)

        cache_coll.update_one({"_id" : event["_id"]}, {"$set":{"processed":True}})
    except:
        logging.error("proc.archive.archive_one: ", exc_info=True)
    
def archive(config):
    n = 0
    while True:
        try:
            cache_coll, archive_backend, fs, private_key_file_path =  decode_archive_config(copy.deepcopy(config))
            cursor = cache_coll.find({"processed":False}).limit(1000)
            for event in cursor: archive_one(event, copy.deepcopy(config))
            event_is = [(event,copy.deepcopy(config)) for event in cursor]

            t1 = time.time()
            pool = multiprocessing.Pool(1)
            results = pool.starmap(archive_one, event_is)
            pool.close()
            pool.join()
            t2 = time.time()
            print(t2-t1)
            n = 0
        except CursorNotFound:
            exponential_backoff(n)
            n += 1
        except Exception:
            logging.error("proc.archive.archive: ", exc_info=True)
            exponential_backoff(n)
            n += 1

    
if __name__ == "__main__":
    archive_config = { 
		"mongo_url" : "mongodb://cybexp_user:CybExP_777@134.197.21.231:27017/?authSource=admin",
		"cache_db" : "cache_test",
		"cache_coll" : "file_entries",
		"archive_db" : "tahoe_db",
		"archive_coll" : "raw",
		"private_key" : "../key/priv.pem"
            }

    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s:%(message)s') # filename = '../proc.log',

    archive(copy.deepcopy(archive_config))

