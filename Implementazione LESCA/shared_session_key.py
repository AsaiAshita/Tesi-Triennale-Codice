from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

def shared_key_creation():
    private_key = ec.generate_private_key(
        ec.SECP521R1()
    )
# In a real handshake the peer_public_key will be received from the
# other party. For this example we'll generate another private key
# and get a public key from that.
    peer_public_key = ec.generate_private_key(
        ec.SECP521R1()
    ).public_key()
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
# Perform key derivation.
    derived_key = HKDF(
        algorithm=hashes.SHA3_512(),
        length=64,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key)
    return derived_key
