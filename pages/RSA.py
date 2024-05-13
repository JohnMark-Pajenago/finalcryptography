import streamlit as st
import random

def is_prime(n):
    if n <= 1:
        return False
    elif n <= 3:
        return True
    elif n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def multiplicative_inverse(e, phi):
    d = 0
    x1 = 0
    x2 = 1
    y1 = 1
    temp_phi = phi

    while e > 0:
        temp1 = temp_phi // e
        temp2 = temp_phi - temp1 * e
        temp_phi = e
        e = temp2

        x = x2 - temp1 * x1
        y = d - temp1 * y1

        x2 = x1
        x1 = x
        d = y1
        y1 = y

    if temp_phi == 1:
        return d + phi

def generate_keypair(p, q):
    if not (is_prime(p) and is_prime(q)):
        raise ValueError("Both numbers must be prime.")
    elif p == q:
        raise ValueError("p and q cannot be equal.")

    n = p * q
    phi = (p - 1) * (q - 1)

    e = random.randrange(1, phi)

    while gcd(e, phi) != 1:
        e = random.randrange(1, phi)

    d = multiplicative_inverse(e, phi)

    return ((e, n), (d, n))

def encrypt(public_key, plaintext):
    key, n = public_key
    cipher = [pow(ord(char), key, n) for char in plaintext]
    return cipher

def decrypt(private_key, ciphertext):
    key, n = private_key
    plain = [chr(pow(char, key, n)) for char in ciphertext]
    return ''.join(plain)

# Streamlit UI
st.title("RSA Encryption and Decryption")

p = st.number_input("Enter prime number p:", value=61, step=1)
q = st.number_input("Enter prime number q:", value=53, step=1)

if st.button("Generate Keys"):
    try:
        public, private = generate_keypair(p, q)
        st.write("Public Key:", public)
        st.write("Private Key:", private)
    except ValueError as e:
        st.error(str(e))

message = st.text_input("Enter your message:")
if st.button("Encrypt"):
    try:
        encrypted_msg = encrypt(public, message)
        st.write("Encrypted message:", ''.join(map(lambda x: str(x), encrypted_msg)))
    except NameError:
        st.error("Please generate keys first.")

encrypted_input = st.text_input("Enter the encrypted message:")
if st.button("Decrypt"):
    try:
        decrypted_msg = decrypt(private, eval(encrypted_input))
        st.write("Decrypted message:", decrypted_msg)
    except NameError:
        st.error("Please generate keys first.")
import streamlit as st
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.exceptions import InvalidSignature

def generate_keypair():
    private_key = dsa.generate_private_key(key_size=1024, backend=default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def sign_message(private_key, message):
    signature = private_key.sign(message.encode(), hashes.SHA256())
    return signature

def verify_signature(public_key, message, signature):
    try:
        public_key.verify(signature.encode(), message.encode(), hashes.SHA256())
        return True
    except InvalidSignature:
        return False

# Streamlit UI
st.title("DSA Signature Verification")

# Generate key pair
private_key, public_key = generate_keypair()

# Input message from the user
message = st.text_input("Enter message")

# Sign the message
if st.button("Sign"):
    signature = sign_message(private_key, message)
    st.success("Message signed successfully!")
    st.write("Signature:", signature.hex())

# Verify signature
input_signature = st.text_input("Enter signature to verify")

if st.button("Verify Signature"):
    verified = verify_signature(public_key, message, input_signature)
    if verified:
        st.success("Signature verified successfully!")
    else:
        st.error("Signature verification failed!")
