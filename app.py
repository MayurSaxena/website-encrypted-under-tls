from flask import Flask, render_template, session, request
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256, SHA384
from Crypto.Protocol.KDF import HKDF
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Signature import pkcs1_15
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

from base64 import b64encode, b64decode
import json
from os.path import isfile
from os import environ
from uuid import uuid4
import redis

app = Flask(__name__)
db=redis.from_url(environ['REDISCLOUD_URL']) # For session to key mapping
# Secret key used for session cookies (there's probably a way to not commit this to Git)
app.secret_key = bytes(bytearray([10,252,182,84,215,72,9,180,194,51,2,202,217,33,183,5]))

# This route kicks off the JavaScript for key negotiation
@app.route("/")
def index():
    h = b64encode(SHA384.new(bytes(loader(), 'utf-8')).digest()).decode('utf-8')
    return render_template('index.html', sri=h)

# Injects the JavaScript with our public RSA key (for identity)
@app.route("/loader")
def loader():
    return render_template('loader.js', pubkey_b64=get_pubkey_b64())

# If it's a GET to main, just serve the content (encrypted)
# If it's a POST, that means someone's trying to log in probably, so decrypt and process
@app.route("/main", methods=["POST", "GET"])
def main_stuff():
    if request.method == "GET":
        return encrypt_for_client(render_template('login.html'))
    if request.json:
        request_json = json.loads(decrypt_from_client(request.json))
        # Show the secret page if the creds are right
        if request_json.get('username') == "user" and request_json.get('pw') == "pass":
            return encrypt_for_client(render_template('account.html'))
        return encrypt_for_client(render_template('login.html', error="Invalid credentials."))
    return('',204)

# Logout will clear the session key and "invalidate" the session UUID
@app.route("/logout")
def logout():
    content = encrypt_for_client(render_template('bye.html'))
    db.delete(session['uuid'])
    session.pop('uuid')
    return content

# The endpoint used for key negotiation
@app.route("/establishkey", methods=["POST"])
def generateSharedKey():
    # Create an ECDH keypair based on curve P-384
    ecdh_private_key = ec.generate_private_key(ec.SECP384R1())
    # Get our public ECDH value as a PEM
    ecdh_public_pem = ecdh_private_key.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    # Public portion from client loaded in to memory as a PEM
    received_public_pem = b64decode(request.form['public_key'])
    loaded_public_key = serialization.load_pem_public_key(received_public_pem)
    # 384-bit shared secret using ECDH - combines our private info with the public point we got from client
    shared_secret = ecdh_private_key.exchange(ec.ECDH(), loaded_public_key)
    # Use the shared secret with HKDF to create a 256-bit AES key
    derived_key = HKDF(shared_secret, 32, b'SaltySalt', SHA256, 1)

    # Store the key on server and tie it to a session UUID (sent to client as a cookie)
    session['uuid'] = str(uuid4())
    db.set(session['uuid'],derived_key)

    # As part of Station-To-Station protocol, sign and encrypt a message with our public info and the public info we got
    # SHA-256 hash of our PEM and the received PEM both as hex strings
    h1 = SHA256.new(ecdh_public_pem).hexdigest()
    h2 = SHA256.new(received_public_pem).hexdigest()
    message_to_sign = f"{h1},{h2}"
    # Sign the message with our private RSA key - public was baked in to the JS
    signature = sign_message(message_to_sign) # comes back as base64 sig
    # Encrypt with the AES key that the client should be able to generate after we send our public ECDH data
    cipher = AES.new(derived_key, AES.MODE_CBC, iv=b'TheSixteenByteIV')
    ct_bytes = cipher.encrypt(pad(bytes(signature, 'utf-8'), AES.block_size))

    # Wrap everything to send in a nice blob (base64ed)
    to_send = {"public_key": b64encode(ecdh_public_pem).decode(), "verification": b64encode(ct_bytes).decode() }
    return to_send

def get_pubkey_b64():
    with open('key.pub','rb') as f:
        contents=f.read()
        return b64encode(contents).decode('utf-8')

def sign_message(msg):
    key = RSA.import_key(open('key').read())
    h = SHA256.new(bytes(msg, 'utf-8'))
    sig = pkcs1_15.new(key).sign(h)
    return b64encode(sig).decode('utf-8')

def decrypt_from_client(cipher_blob):
    # cipher_blob should be a dictionary with two elements: iv and ciphertext
    # the data for those two elements should be Base64-encoded
    # The key is tied to the session UUID
    if db.get(session['uuid']) is None:
        print(f"ERROR: No key found to decrypt for UUID {session['uuid']}.")
    cipher = AES.new(db.get(session['uuid']), AES.MODE_CBC, iv=b64decode(cipher_blob.get('iv')))
    ct_bytes = unpad(cipher.decrypt(b64decode(cipher_blob.get('ciphertext'))), AES.block_size)
    return ct_bytes.decode('utf-8')

def encrypt_for_client(content):
    # The key is tied to the session UUID
    if db.get(session['uuid']) is None:
        print(f"ERROR: No key found to encrypt for UUID {session['uuid']}.")

    cipher = AES.new(db.get(session['uuid']), AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(bytes(content, 'utf-8'), AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    return json.dumps({'iv':iv, 'ciphertext':ct})

@app.before_first_request
def generate_identity_keypair():
    # Generate an RSA keypair for identity and signing if it doesn't exist
    if not isfile('key') or not isfile('key.pub'):
        key = RSA.generate(2048)
        with open('key', 'wb') as f:
            f.write(key.export_key('PEM'))
        with open('key.pub', 'wb') as f:
            f.write(key.publickey().export_key('PEM'))