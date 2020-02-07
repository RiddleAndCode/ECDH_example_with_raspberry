import requests
from base64 import b64encode, b64decode
import json
import os
from Crypto.PublicKey import ECC
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Signature import DSS
from SEAL import SEAL

class Utils:
    @staticmethod
    def public_key_bytes_to_key(key_bytes, curve='P-256'):
        return ECC.construct(point_x=bytes_to_long(key_bytes[1:33]), point_y=bytes_to_long(key_bytes[33:]), curve=curve)

    @staticmethod
    def public_key_bytes_to_point(key_bytes, curve='P-256'):
        return ECC.EccPoint(bytes_to_long(key_bytes[1:33]), bytes_to_long(key_bytes[33:]), curve)

    @staticmethod
    def point_to_public_key_bytes(point):
        return bytes([4]) + long_to_bytes(point.x) + long_to_bytes(point.y)

class KeyPair:
    def __init__(self, key):
        self.key = key

    @staticmethod
    def generate(curve='P-256'):
        # TODO use randfunc from seal
        return KeyPair(ECC.generate(curve=curve))

    @staticmethod
    def from_public_key_bytes(public_key_bytes, curve='P-256'):
        return KeyPair(Utils.public_key_bytes_to_key(public_key_bytes, curve))

    def public_point(self):
        return self.key.pointQ

    def public_key_bytes(self):
        return Utils.point_to_public_key_bytes(self.public_point())

    def scalar_multiply(self, point):
        return point * self.key.d

    def verify(self, message, signature):
        h = SHA256.new(message)
        verifier = DSS.new(self.key, 'fips-186-3')
        verifier.verify(h, signature)

class SharedSecret:
    def __init__(self, key_material):
        self.key_material = key_material

    def encrypt(self, message):
        ciphertext, tag = self._aes_128_gcm().encrypt_and_digest(message)
        return ciphertext + tag

    def decrypt(self, message):
        return self._aes_128_gcm().decrypt(message)[:-16]
    
    def _aes_128_gcm(self):
        key_bytes = HKDF(self.key_material, 16, b'', SHA256)
        return AES.new(key_bytes, AES.MODE_GCM, nonce=bytes(12))

class EphemeralKeyPair:
    def __init__(self, key):
        self.key = key

    def create_shared_secret(self, other_ephemeral):
        return SharedSecret(self._create_shared_secret_material(other_ephemeral))

    def _create_shared_secret_material(self, other_ephemeral):
        new_point = self.key.scalar_multiply(other_ephemeral.key.public_point())
        return Utils.point_to_public_key_bytes(new_point)[1:33]

class SealKeyPair:
    def __init__(self, seal, key_index=0):
        self.key_index = key_index
        self.seal = seal
        self.curve = 'P-256' 

    def sign(self, message):
        # TODO use seal hash function
        hashed = SHA256.new(message).digest()
        return self.seal.sign(self.key_index, hashed)

    def public_key_bytes(self):
        return bytes([4]) + self.seal.get_public_key(self.key_index)

    def public_point(self):
        return Utils.public_key_bytes_to_point(self.public_key_bytes(), self.curve)


# config
current_dir = os.path.dirname(os.path.abspath(__file__))
seal = SEAL(current_dir + "/../libs/raspberry/v1/libseadyn.so")
service = "http://192.168.23.26:4000"
server_pub_key = "BJzNphRprGYTt7ioyifaRqMQQW758qBhZBAlMo6tUbo4C9GeQLUsI6CvjtFaVWXKDKLqp9RUUaHVeEX0RcX/GM4="

# get static key pairs
server_key_pair = KeyPair.from_public_key_bytes(b64decode(server_pub_key))
my_key_pair = SealKeyPair(seal)

# create ephemeral key pair and sign
my_ephemeral = EphemeralKeyPair(KeyPair.generate())
ephemeral_public_key = my_ephemeral.key.public_key_bytes()
signature = my_key_pair.sign(ephemeral_public_key)

# get server ephemeral public key
headers = {'X-PublicKey': b64encode(my_key_pair.public_key_bytes()).decode('utf-8')}
req = {'ephemeral_public_key': b64encode(ephemeral_public_key).decode('utf-8'),
            'signature': b64encode(signature).decode('utf-8')}
res = requests.post(service + "/session", headers=headers, json=req).json()
server_ephemeral = b64decode(res['ephemeral_public_key'])
server_signature = b64decode(res['signature'])

# check server signature
server_key_pair.verify(server_ephemeral, server_signature)

# get shared secret
server_ephemeral = EphemeralKeyPair(KeyPair.from_public_key_bytes(server_ephemeral))
shared_secret = my_ephemeral.create_shared_secret(server_ephemeral)

# use shared secret to encrypt
headers = {'X-PublicKey': b64encode(my_key_pair.public_key_bytes()).decode('utf-8')}
req = {'name': 'julian'}
payload = b64encode(shared_secret.encrypt(json.dumps(req).encode('utf-8')))
res = b64decode(requests.post(service + "/greeting", headers=headers, data=payload).text)

# use shared secret to decrypt
res = shared_secret.decrypt(res)
print(res)
