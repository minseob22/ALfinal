import hashlib

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def modinv(a, m):
    m0, y, x = m, 0, 1
    if m == 1:
        return 0
    while a > 1:
        q = a // m
        t = m
        m = a % m
        a = t
        t = y
        y = x - q * y
        x = t
    if x < 0:
        x += m0
    return x

def generate_keys(p, q):
    n = p * q
    phi = (p - 1) * (q - 1)
    
    e = 65537
    print(f"Initial e value: {e}")
    while gcd(e, phi) != 1:
        e += 2
        print(f"Trying next e value: {e}")
    
    print(f"Selected e value: {e}")
    
    # Calculate d, the modular inverse of e
    d = modinv(e, phi)
    return (e, n), (d, n)

def hash_message(message, n):
    hash_value = int(hashlib.sha256(message.encode()).hexdigest(), 16)
    return hash_value % n

def sign_message(message, private_key):
    d, n = private_key
    message_hash = hash_message(message, n)
    signature = pow(message_hash, d, n)
    return signature

def verify_signature(message, signature, public_key):
    e, n = public_key
    message_hash = hash_message(message, n)
    verified_hash = pow(signature, e, n)

    # Print the hash values for comparison
    print(f"Original message hash: {message_hash}")
    print(f"Decrypted signature hash: {verified_hash}")

    return message_hash == verified_hash


p = 32416190071  
q = 32416187567 

# Key generation
public_key, private_key = generate_keys(p, q)
print(f"Public key: {public_key}")
print(f"Private key: {private_key}")

# Message input and signing
message = "hello"
signature = sign_message(message, private_key)
print(f"Signature: {signature}")

# Signature verification
is_valid = verify_signature(message, signature, public_key)
print(f"Signature verification result: {'Valid' if is_valid else 'Invalid'}")
