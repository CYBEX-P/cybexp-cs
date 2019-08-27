# =========== Encryption ========================

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

