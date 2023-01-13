import javaobj
import base64

# pip3 install javaobj-py3
with open(".cobaltstrike.beacon_keys", "rb") as f:
    key = javaobj.loads(f.read())
priv = bytes(c & 0xFF for c in key.array.value.privateKey.encoded)
pub = bytes(c & 0xFF for c in key.array.value.publicKey.encoded)

print("-----BEGIN RSA PRIVATE KEY-----")
print(base64.encodebytes(priv).strip().decode())
print("-----END RSA PRIVATE KEY-----")
print("")

print("-----BEGIN PUBLIC KEY-----")
print(base64.encodebytes(pub).strip().decode())
print("-----END PUBLIC KEY-----")
