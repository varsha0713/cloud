from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.asymmetric import ec

from cryptography.hazmat.primitives import serialization

private_key=ec.generate_private_key(ec.SECP256R1())

public_key=private_key.public_key()

public_pem=public_key.public_bytes(

encoding=serialization.Encoding.PEM,

format=serialization.PublicFormat.SubjectPublicKeyInfo)

print("public key pem format: \n",public_pem.decode())

message=input("enter a message to be signed:").encode()

signature=private_key.sign(message, ec. ECDSA(hashes.SHA256()))

print("signature", signature)

try:
     public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
     print("Signature is valid")
except:
    print("signature is failed")


