def generate_public_key(prime,base,private_key):
    return pow(base,private_key,prime)
def generate_shared_secret(public_key,private_key,prime):
    return pow(public_key,private_key,prime)
prime=int(input("enter the large prime number"))
base=int(input("enter the base"))
alice_private_key=int(input("enter alice private key"))
alice_public_key=generate_public_key(prime,base,alice_private_key)
print("alice public key",alice_public_key)

bob_private_key=int(input("enter bobs prvate key"))
bob_public_key=generate_public_key(prime,base,bob_private_key)
print("bob public key",bob_public_key)

alice_shared=generate_shared_secret(bob_public_key,alice_private_key,prime)
bob_shared=generate_shared_secret(alice_public_key,bob_private_key,prime)

print("alice shared key",alice_shared)
print("bob shared key",bob_shared)

if alice_shared==bob_shared:
    print("success,the shared secret is",alice_shared)
else:
    print("error")


