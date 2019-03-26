from pymongo import MongoClient
import gridfs
import pdb
from io import BytesIO

URI = 'mongodb://cybexp_user:CybExP_777@134.197.21.231:27017/?authSource=admin'
client = MongoClient(URI)
db = client.cache_db
coll = db.file_entries
fs = gridfs.GridFS(db)

e = coll.find_one({'processed':True})
fid = e['fid']
f = fs.get(fid)
f = f.read()


def encrypt_file(fbytes, fpub_name="pub.pem"):
    
    from Crypto.PublicKey import RSA
    from Crypto.Random import get_random_bytes
    from Crypto.Cipher import AES, PKCS1_OAEP

    din = fbytes

    pubkey = RSA.import_key(open(fpub_name).read())
    session_key = get_random_bytes(32)

    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(pubkey)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Encrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(din)
    dout = enc_session_key + cipher_aes.nonce + tag + ciphertext
    return dout

def decrypt_file(file_in, fpriv_name="priv.pem"):
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import AES, PKCS1_OAEP

    if type(file_in) == 'bytes': file_in = BytesIO(file_in)

    private_key = RSA.import_key(open(fpriv_name).read())

    enc_session_key, nonce, tag, ciphertext = \
       [ file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]


    # Decrypt the session key with the private RSA key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    # Decrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    return data.decode("utf-8")


fenc = encrypt_file(f)
fdec = decrypt_file(fenc)
