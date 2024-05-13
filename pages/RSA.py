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
