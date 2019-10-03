import io, time, gridfs, logging, json, copy, random, multiprocessing, os, pdb
from pymongo import MongoClient
from pymongo.errors import CursorNotFound
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP

if __name__ == "__main__":
    archive_config = {
        "mongo_url": "mongodb://cybexp_user:CybExP_777@134.197.21.231:27017/?authSource=admin",
        "cache_db": "cache_db",
        "cache_coll": "file_entries",
        "archive_db": "tahoe_db",
        "archive_coll": "instances",
        "private_key": "../key/priv.pem",
    }


def decrypt_file(file_in, fpriv_name="priv.pem"):
    if isinstance(file_in, bytes):
        file_in = io.BytesIO(file_in)
    private_key = RSA.import_key(open(fpriv_name).read())
    enc_session_key, nonce, tag, ciphertext = [
        file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1)
    ]

    # Decrypt the session key with the private RSA key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    # Decrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)

    return data.decode("utf-8")


def exponential_backoff(n):
    s = min(3600, (2 ** n) + (random.randint(0, 1000) / 1000))
    time.sleep(s)


def archive_one(event, cache_coll, fs, pkey_fp, parsemain):
    try:
        typtag = event["typtag"]
        orgid = event["orgid"]
        upload_time = event["datetime"]
        timezone = event["timezone"]

        fid = event["fid"]
        f = fs.get(fid)
        data = str(decrypt_file(f, pkey_fp))

        raw = parsemain(typtag, orgid, timezone, data)

        if raw:
            cache_coll.update_one(
                {"_id": event["_id"]},
                {"$set": {"processed": True}, "$addToSet": {"_ref": raw.uuid}},
            )
            return True
        else:
            return False
    except gridfs.errors.CorruptGridFile:
        cache_coll.update_one(
            {"_id": event["_id"]},
            {"$set": {"processed": True}, "$set": {"bad_data": True}},
        )
        return False
    except:
        logging.error("proc.archive.archive_one: -- ", exc_info=True)
        return False


def archive(config):
    n_failed_attempts = 0
    while True:
        try:
            conf = copy.deepcopy(config)
            mongo_url = conf.pop("mongo_url")
            client = MongoClient(mongo_url)
            cache_db = client.get_database(conf.pop("cache_db", "cache_db"))
            cache_coll = cache_db.get_collection(conf.pop("cache_coll", "file_entries"))
            fs = gridfs.GridFS(cache_db)
            private_key_file_path = conf.pop("private_key", "priv.pem")

            os.environ["_MONGO_URL"] = mongo_url
            os.environ["_TAHOE_DB"] = conf.pop("archive_db", "tahoe_db")
            os.environ["_TAHOE_COLL"] = conf.pop("archive_coll", "instances")

            from parsemain import parsemain  # don't move to top

            break

        except:
            logging.error(
                "proc.archive.archive 1: Error connecting to database -- ",
                exc_info=True,
            )
            exponential_backoff(n_failed_attempts)
            n_failed_attempts += 1

    while True:
        try:
            cursor = cache_coll.find({"processed": False}).limit(10000)
            any_success = False
            for e in cursor:
                s = archive_one(e, cache_coll, fs, private_key_file_path, parsemain)
                any_success = any_success or s

            if any_success:
                n_failed_attempts = 0
            else:
                n_failed_attempts += 1

        except CursorNotFound:
            n_failed_attempts += 1

        except Exception:
            logging.error("proc.archive.archive: ", exc_info=True)
            n_failed_attempts += 1

        exponential_backoff(n_failed_attempts)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.DEBUG, format="%(asctime)s %(levelname)s:%(message)s"
    )  # filename = 'archive.log',

    archive(copy.deepcopy(archive_config))
