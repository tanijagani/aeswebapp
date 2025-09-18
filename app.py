from flask import Flask, render_template, request
from Crypto.Cipher import AES
import base64

app = Flask(__name__)

# Padding helper functions
def pad(s):
    return s + (16 - len(s) % 16) * chr(16 - len(s) % 16)

def unpad(s):
    return s[:-ord(s[-1])]

# Home route
@app.route('/')
def home():
    return render_template('index.html')

# Encrypt / Decrypt route
@app.route('/encrypt_decrypt', methods=['GET', 'POST'])
def encrypt_decrypt():
    result = None
    if request.method == 'POST':
        text = request.form['text']
        key = request.form['key']
        action = request.form['action']

        key = pad(key)[:16].encode('utf-8')  # AES key must be 16 bytes

        cipher = AES.new(key, AES.MODE_ECB)

        if action == 'encrypt':
            encrypted = cipher.encrypt(pad(text).encode('utf-8'))
            result = base64.b64encode(encrypted).decode('utf-8')
        elif action == 'decrypt':
            try:
                decrypted = cipher.decrypt(base64.b64decode(text))
                result = unpad(decrypted.decode('utf-8'))
            except:
                result = "Invalid key or text!"
    return render_template('encrypt_decrypt.html', result=result)

if __name__ == '__main__':
    app.run(debug=True)
