import streamlit as st

st.header("XOR Cipher")
st.text('by John Mark A. Pajenago')


def xor_encrypt(plaintext, key):
    """Encrypts plaintext using XOR cipher with the given key."""
    ciphertext = bytearray()
    for i in range(len(plaintext)):
        input_text_byte = plaintext[i]
        key_byte = key[i % len(key)]
        encrypted_byte = input_text_byte ^ key_byte
        ciphertext.append(encrypted_byte)
    return ciphertext


def xor_decrypt(ciphertext, key):
    """Decrypts ciphertext using XOR cipher with the given key."""
    return xor_encrypt(ciphertext, key)  # XOR decryption is the same as encryption


def main():
    st.title("XOR Cipher Encryption App")

    mode = st.sidebar.radio("Mode", ("Encrypt Text", "Decrypt Text", "Encrypt File", "Decrypt File"))

    key = st.sidebar.text_input("Enter Key")

    if mode == "Encrypt Text":
        text = st.text_area("Enter Text to Encrypt")
        if st.button("Encrypt"):
            encrypted_text = xor_encrypt(text.encode(), key.encode())
            st.text_area("Encrypted Text", value=encrypted_text.decode(), height=200)

    elif mode == "Decrypt Text":
        text = st.text_area("Enter Text to Decrypt")
        if st.button("Decrypt"):
            decrypted_text = xor_decrypt(text.encode(), key.encode())
            st.text_area("Decrypted Text", value=decrypted_text.decode(), height=200)

    elif mode == "Encrypt File":
        file = st.file_uploader("Upload File to Encrypt", type=["txt"])
        if st.button("Encrypt File"):
            if file is not None:
                file_contents = file.read()
                encrypted_file_contents = xor_encrypt(file_contents, key.encode())
                st.text_area("Encrypted File Contents", value=encrypted_file_contents.decode(), height=200)
            else:
                st.error("Please upload a text file.")

    elif mode == "Decrypt File":
        file = st.file_uploader("Upload File to Decrypt", type=["txt"])
        if st.button("Decrypt File"):
            if file is not None:
                file_contents = file.read()
                decrypted_file_contents = xor_decrypt(file_contents, key.encode())
                st.text_area("Decrypted File Contents", value=decrypted_file_contents.decode(), height=200)
            else:
                st.error("Please upload a text file.")

if __name__ == "__main__":
    main()
