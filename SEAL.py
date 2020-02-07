import ctypes
import base58
import binascii
DEBUG = False


class SEAL:



    def __init__(self, library_path=None):
        """
        Args:
            library_path <str> : Full path to the compiled file of microECC library (libmicroecc.so)
            curve_name <str> : "secp256r1" (default), "secp160r1", "secp192r1", "secp224r1", "secp256k1"
        """
        self.PUB_KEY_SLOT = 14
        self.SEC_KEY_SLOT = 15
        self.result = -1
        self.lib = ctypes.CDLL(library_path or 'libseadyn.so')
        self.se_init = self.wrap_function(self.lib,"se_init",ctypes.c_int,[ctypes.c_int])
        self.ses_init = self.wrap_function(self.lib,"se_secure_storage_init",ctypes.c_int,[])
        self.se_get_random =self.wrap_function(self.lib,"se_get_random",ctypes.c_int,[ctypes.POINTER(ctypes.c_uint8),ctypes.c_uint8])
        self.se_write_data =self.wrap_function(self.lib,"se_write_data",ctypes.c_int,[ctypes.c_uint8,ctypes.POINTER(ctypes.c_ubyte),ctypes.c_uint8])
        self.se_read_data =self.wrap_function(self.lib,"se_read_data",ctypes.c_int,[ctypes.c_ushort,ctypes.POINTER(ctypes.c_uint8),ctypes.c_ushort])
        self.se_get_pubkey =self.wrap_function(self.lib,"se_get_pubkey",ctypes.c_int,[ctypes.c_uint8,ctypes.POINTER(ctypes.c_uint8),ctypes.POINTER(ctypes.c_ushort)])
        self.se_get_sha256 =self.wrap_function(self.lib,"se_get_sha256",ctypes.c_int,[ctypes.c_char_p,ctypes.c_uint8,ctypes.POINTER(ctypes.c_uint8),ctypes.POINTER(ctypes.c_uint8)])
        self.se_sign =self.wrap_function(self.lib,"se_sign",ctypes.c_int,[ctypes.c_uint8,ctypes.POINTER(ctypes.c_uint8),ctypes.c_ushort,ctypes.POINTER(ctypes.c_uint8),ctypes.POINTER(ctypes.c_uint8)])
        self.se_verify =self.wrap_function(self.lib,"se_verify_external",ctypes.c_int,[ctypes.c_uint8,ctypes.POINTER(ctypes.c_uint8),ctypes.c_ushort,ctypes.POINTER(ctypes.c_uint8),ctypes.c_ushort,ctypes.POINTER(ctypes.c_uint8),ctypes.c_ushort])
        self.se_authenticate =self.wrap_function(self.lib,"se_authenticate",ctypes.c_int,[ctypes.c_uint8,ctypes.POINTER(ctypes.c_uint8)])
        self.se_secure_store =self.wrap_function(self.lib,"se_secure_store",ctypes.c_int,[ctypes.c_uint8,ctypes.POINTER(ctypes.c_uint8),ctypes.c_uint8])
        self.se_secure_read =self.wrap_function(self.lib,"se_secure_read",ctypes.c_int,[ctypes.c_uint8,ctypes.POINTER(ctypes.c_uint8),ctypes.c_uint8])
        self.se_close= self.wrap_function(self.lib,"se_close",ctypes.c_int,[])
        self.ses_close= self.wrap_function(self.lib,"se_secure_storage_close",ctypes.c_int,[])



        result = self.se_init(ctypes.c_int(0))
        if result != 0:
            raise Exception('SE Init failed')
        else:
            if DEBUG:
                print("SE Init Success\n")

        result = self.ses_init()
        if result != 0:
            raise Exception('SES Init failed')
        else:
            if DEBUG:
                print("SES Init Success\n")


    def wrap_function(self,lib, funcname, restype, argtypes):
        """Simplify wrapping ctypes functions"""
        func = lib.__getattr__(funcname)
        func.restype = restype
        func.argtypes = argtypes
        return func

    def close_comms(self):
        result = self.se_close()
        if result != 0:
            raise Exception('i2c close failed')
        else:
            if DEBUG:
                print("SE se_close Success\n")
        result = self.ses_close()
        if result != 0:
            raise Exception('i2c close failed')
        else:
            if DEBUG:
                print("SE se_close Success\n")

    def get_random(self):
        random_buffer = ((ctypes.c_uint8) * 32 )()
        result = self.se_get_random(random_buffer,32)
        if result != 0:
            raise Exception('rnd generation failed')
        else:
            if DEBUG:
                print("SE se_get_random Success\n")
        return random_buffer


    def save_keypair(self,pubKey,secret):
        result = self.store_data(self.PUB_KEY_SLOT,(ctypes.c_ubyte*32).from_buffer_copy(base58.b58decode(pubKey)),32)
        if result != 0:
            raise Exception('se_save_key_pair failed')
        else:
            self.store_data(self.SEC_KEY_SLOT,(ctypes.c_ubyte*32).from_buffer_copy(base58.b58decode(secret)),32)
            if DEBUG:
                print("SE se_save_key_pair Success\n")

    def store_data(self,slot,data,datalen):
        result = self.se_write_data(slot,data,datalen)
        if result != 0:
            raise Exception('se_write_data failed')
        else:
            if DEBUG:
                print("SE se_write_data Success\n")
        return result


    def read_data(self,slot,datalen):

        data = ((ctypes.c_uint8) * datalen )()
        result = self.se_read_data(slot,data,datalen)
        if result != 0:
            raise Exception('read_data failed')
        else:
            if DEBUG:
                print("SE se_read_data Success\n")
        return bytes(data)

    def get_public_key(self,slot):
        pubKey = ((ctypes.c_uint8) * 64 )()
        result = self.se_get_pubkey(slot,pubKey,None)
        if result != 0:
            raise Exception('get_public_key failed')
        else:
            if DEBUG:
                print("SE se_get_pubkey Success\n")
        return bytes(bytearray(pubKey)[:64])

    def get_hash(self,data,dataLen):
        b_data = str(data).encode('utf-8')
        sha = ((ctypes.c_uint8) * 32 )()
        shaLen = ((ctypes.c_uint8) * 2 )(32)
        result = self.se_get_sha256(b_data,dataLen,sha,shaLen)
        if result != 0:
            raise Exception('get_hash failed')
        else:
            if DEBUG:
                print("SE get_hash Success\n")
        return bytes(sha)

    def sign(self,slot,message):
        signature = ((ctypes.c_uint8) * 64 )()
        str_len = len(message)
        # (ctypes.c_ubyte*str_len).from_buffer_copy(message.encode())
        result = self.se_sign(slot,(ctypes.c_ubyte*str_len).from_buffer_copy(message),0,signature,None)
        if result != 0:
            raise Exception('sign failed')
        else:
            if DEBUG:
                print("SE sign Success\n")
        return bytes((signature))

    def verify(self,hash,signature,publickey):
        hash_len = len(hash)
        signature_len = len(signature)
        publickey_len = len(publickey)
        result = self.se_verify(0,(ctypes.c_ubyte*publickey_len).from_buffer_copy(publickey),0,(ctypes.c_ubyte*hash_len).from_buffer_copy(hash),0,(ctypes.c_ubyte*signature_len).from_buffer_copy(signature),0)
        if result != 0xF6:
            raise Exception('verify failed')
            return False
        else:
            if DEBUG:
                print("SE verify Success\n")
            return True

    def authenticate_slot(self,slot,secret):
        str_len = len(secret)
        result = self.se_authenticate(slot,(ctypes.c_ubyte*str_len).from_buffer_copy(secret.encode()))
        if result != 0:
            raise Exception('authenticate_slot failed')
        else:
            if DEBUG:
                print("SE authenticate_slot Success\n")
        return result

    def secure_store(self,slot,data,size):
        result = self.se_secure_store(slot,(ctypes.c_ubyte*size).from_buffer_copy(data.encode()),size)
        if result != 0:
            raise Exception('secure_store failed')
        else:
            if DEBUG:
                print("SE secure_store Success\n")
        return result

    def secure_read(self,slot,size):
        data = ((ctypes.c_uint8) * size )()
        result = self.se_secure_read(slot,data,size)

        if result != 0:
            raise Exception('secure_read failed')
        else:
            if DEBUG:
                print("SE secure_read Success\n")
        return bytes(data)


