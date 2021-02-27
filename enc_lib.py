from nummaster.basic import sqrtmod
from Crypto.Cipher import AES
from Crypto.PublicKey.ECC import import_key
import hashlib, secrets, binascii
from tinyec import registry
from tinyec.ec import Point

curve = registry.get_curve('brainpoolP256r1')

# ENCRYPTION STUFF
def encrypt_AES_GCM(msg, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
    return (ciphertext, aesCipher.nonce, authTag)

def decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return plaintext

def ecc_point_to_256_bit_key(point):
    sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
    sha.update(int.to_bytes(point.y, 32, 'big'))
    return sha.digest()

#encrypt message with public key
def encrypt_ECC(msg, pubKey):
    ciphertextPrivKey = secrets.randbelow(curve.field.n)
    sharedECCKey = ciphertextPrivKey * pubKey
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    ciphertext, nonce, authTag = encrypt_AES_GCM(msg, secretKey)
    ciphertextPubKey = ciphertextPrivKey * curve.g
    return (ciphertext, nonce, authTag, ciphertextPubKey)

#decrypt message with private key
def decrypt_ECC(encryptedMsg, privKey):
    (ciphertext, nonce, authTag, ciphertextPubKey) = encryptedMsg
    sharedECCKey = privKey * ciphertextPubKey
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    plaintext = decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey)
    return plaintext

#Compress public key for giving to other users
def compress_point(point):
    return hex(point.x) + hex(point.y % 2)[2:]

#decompress hex key back to Point object for use in encryption
def uncompress_to_point(curve, compressed_key):
    x, is_odd = compressed_key[0:-1], compressed_key[-1]
    p, a, b = curve.g.p, curve.a, curve.b
    x = int(x,16)
    is_odd = int(is_odd)
    y = sqrtmod(pow(x, 3, p) + a * x + b, p)
    if bool(is_odd) == bool(y & 1):
        return Point(curve, x, y)
    return Point(curve,x, p - y)

#covnert the encrypted message hex string back to a list of bytes and point object
#and call decrypt_ECC function
def decrypt_from_string(encryptedMsg, privKey):
    try:
        encryptedMsg = encryptedMsg.split(',')
        encryptedMsg = [bytes.fromhex(e) for e in encryptedMsg[0:3]] + [(encryptedMsg[3])]
        encryptedMsg = encryptedMsg[0:3] + [uncompress_to_point(curve,encryptedMsg[3])]
        return str(decrypt_ECC(encryptedMsg, privKey))[2:-1]
    except:
        return 'Cannot decrypt message!'

#prepare the encrypted message as a hex string representation for adding to the chain
def encrypt_to_string(msg, pubKey):
    encryptedMsg = encrypt_ECC(msg, pubKey)
    encryptedMsg = [e.hex() for e in encryptedMsg[0:3]] + [compress_point(encryptedMsg[3])]
    return ','.join(encryptedMsg)