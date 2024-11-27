def gcd(a, b):
	while b != 0:
    	a, b = b, a % b
	return a
 
def modinv(e, phi):
	d, x1, x2, y1 = 0, 0, 1, 1
	temp_phi = phi
	while e > 0:
    	temp1, temp2 = divmod(temp_phi, e)
    	temp_phi, e = e, temp2
    	x = x2 - temp1 * x1
    	y = d - temp1 * y1
    	x2, x1 = x1, x
    	d, y1 = y1, y
	if temp_phi == 1:
    	return d + phi
 
def generate_keypair(p, q):
	n = p * q
	phi = (p - 1) * (q - 1)
	e = 17  
	g = gcd(e, phi)
	while g != 1:
    		e += 1
    		g = gcd(e, phi)
	d = modinv(e, phi)
	return ((e, n), (d, n))
 
def encrypt(pk, plaintext):
	key, n = pk
	cipher = [pow(ord(char), key, n) for char in plaintext]
	return cipher
 
def decrypt(pk, ciphertext):
	key, n = pk
	plain = [chr(pow(char, key, n)) for char in ciphertext]
	return ''.join(plain)
 
if _name_ == '_main_':
	
	p = int(input("Enter a prime number (p): "))
	q = int(input("Enter another prime number (q): "))
 
	
	public, private = generate_keypair(p, q)
	print(f"Public Key: {public}")
	print(f"Private Key: {private}")
 
	
	message = input("Enter the message to encrypt: ")
 
	
	encrypted_msg = encrypt(public, message)
	print(f"Encrypted message: {encrypted_msg}")
 
	
	decrypted_msg = decrypt(private, encrypted_msg)
	print(f"Decrypted message: {decrypted_msg}")

