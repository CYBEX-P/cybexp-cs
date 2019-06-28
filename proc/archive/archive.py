import io, time, gridfs, logging, json, copy, pdb
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
    archive_coll = config.pop("archive_coll", "raw")
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

def archive(config):
    try:
        cache_coll, archive_backend, fs, private_key_file_path =  decode_archive_config(config)
    
        cursor = cache_coll.find({"processed":False})
        for event in cursor:
            upload_time = event['datetime']
            orgid = event['orgid']
            typtag = event['typtag']
            timezone = event['timezone']
            fid = event['fid']
            f = fs.get(fid)
        
            data = str(decrypt_file(f, private_key_file_path))
            instance = parsemain(data, orgid, typtag, timezone, archive_backend)
        
            cache_coll.update_one({"_id" : event["_id"]}, {"$set":{"processed":True}})

    except CursorNotFound: time.sleep(600)
    except Exception: logging.error("Exception in archive()", exc_info=True)
    
if __name__ == "__main__":
    archive_config = { 
		"mongo_url" : "mongodb://cybexp_user:CybExP_777@134.197.21.231:27017/?authSource=admin",
		"cache_db" : "cache_test",
		"cache_coll" : "file_entries",
		"archive_db" : "tahoe_db",
		"archive_coll" : "raw",
		"private_key" : "../key/priv.pem"
            }

    logging.basicConfig(filename = '../proc.log', level=logging.DEBUG, format='%(asctime)s %(levelname)s:%(message)s') # filename = '../proc.log',
 
    while True:
        archive(copy.deepcopy(archive_config))

