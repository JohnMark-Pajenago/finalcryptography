import streamlit as st

st.header("Caesar Cipher")


def encrypt_decrypt(text, shift_keys, ifdecrypt):
    """Encrypts or decrypts text using the Caesar Cipher.

    Args:
        text: The text to process.
        shift_keys: A list of integer shift values.
        encrypt: True for encryption, False for decryption.

    Returns:
        The processed text.
    """

    result = ""
    if len(shift_keys) <= 1:
        raise ValueError("Invalid")
        
    for i, char in enumerate(text):
        shift = shift_keys[i % len(shift_keys)]
        
        if 32 <= ord(char) <= 125:
            new_ascii = ord(char) + shift if not ifdecrypt else ord(char) - shift
            while new_ascii > 125:
                new_ascii -= 94
            while new_ascii < 32:
                new_ascii += 94
                
            result += chr(new_ascii)
        else:
            result += char
    return result

def caesar_encrypt(message, keys):
    return encrypt_decrypt(message, keys, False)

def caesar_decrypt(encrypted_text, keys):
    return encrypt_decrypt(encrypted_text, keys, True)

def main():
    st.title("Caesar Cipher Encryption App")

    mode = st.sidebar.radio("Mode", ("Encrypt Text", "Decrypt Text", "Encrypt File", "Decrypt File"))

    keys_input = st.sidebar.text_input("Enter Key (Shifts) separated by spaces", "3 5 7")
    keys = [int(key) for key in keys_input.split()]

    if mode == "Encrypt Text":
        text = st.text_area("Enter Text to Encrypt")
        if st.button("Encrypt"):
            encrypted_text = caesar_encrypt(text, keys)
            st.text_area("Encrypted Text", value=encrypted_text, height=200)
    
    elif mode == "Decrypt Text":
        text = st.text_area("Enter Text to Decrypt")
        if st.button("Decrypt"):
            decrypted_text = caesar_decrypt(text, keys)
            st.text_area("Decrypted Text", value=decrypted_text, height=200)

    elif mode == "Encrypt File":
        file = st.file_uploader("Upload File to Encrypt", type=["txt"])
        if st.button("Encrypt File"):
            if file is not None:
                file_contents = file.read().decode("utf-8")
                encrypted_file_contents = caesar_encrypt(file_contents, keys * (len(file_contents) // len(keys)) + keys[:len(file_contents) % len(keys)])
                st.text_area("Encrypted File Contents", value=encrypted_file_contents, height=200)
            else:
                st.error("Please upload a text file.")

    elif mode == "Decrypt File":
        file = st.file_uploader("Upload File to Decrypt", type=["txt"])
        if st.button("Decrypt File"):
            if file is not None:
                file_contents = file.read().decode("utf-8")
                decrypted_file_contents = caesar_decrypt(file_contents, keys * (len(file_contents) // len(keys)) + keys[:len(file_contents) % len(keys)])
                st.text_area("Decrypted File Contents", value=decrypted_file_contents, height=200)
            else:
                st.error("Please upload a text file.")

if __name__ == "__main__":
    main()
