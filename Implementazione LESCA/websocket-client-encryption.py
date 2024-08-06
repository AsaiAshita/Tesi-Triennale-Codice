#!/usr/bin/env python

import asyncio
import websockets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from Lesca import lesca_encrypt, lesca_decrypt, initialization

async def shared_key_creation(websocket):
    private_key = ec.generate_private_key(
        ec.SECP521R1()
    )
    public_key = private_key.public_key()
    public_key = public_key.public_bytes(Encoding.X962,PublicFormat.UncompressedPoint)
    #otteniamo la chiave pubblica del nostro interlocutore, poi inviamo la nostra
    peer_public_key = await websocket.recv()
    await websocket.send(bytes(public_key))
    peer_public_key = EllipticCurvePublicKey.from_encoded_point(ec.SECP521R1(), peer_public_key)
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    # Perform key derivation.
    derived_key = HKDF(
        algorithm=hashes.SHA3_512(),
        length=64,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key)
    return derived_key

async def lesca_connection():
    uri = "ws://localhost:8765"
    async with websockets.connect(uri) as websocket:
        session_key = await shared_key_creation(websocket)
        V, perm1, perm2, perm3, perm4 = initialization("0"*512,session_key)
        msg = input("Input the message that you are going to send to the other client for encryption: ")
        msg_encrypt = lesca_encrypt(msg, V, perm1, perm2, perm3, perm4)
        await websocket.send(msg_encrypt)
        msg_in = await websocket.recv()
        msg_decrypt = lesca_decrypt(msg_in, V, perm1, perm2, perm3, perm4)
        print("MESSAGE ARRIVED!")
        print(msg_decrypt)

if __name__ == "__main__":
    asyncio.run(lesca_connection())
