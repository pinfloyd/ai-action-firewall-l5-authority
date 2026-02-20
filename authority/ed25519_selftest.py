import cryptography
from cryptography.hazmat.primitives.asymmetric import ed25519

print("CRYPTOGRAPHY_VERSION=", cryptography.__version__)

# self-test
priv = ed25519.Ed25519PrivateKey.generate()
pub = priv.public_key()

msg = b"test"
sig = priv.sign(msg)
pub.verify(sig, msg)

print("ED25519_SELFTEST=OK")