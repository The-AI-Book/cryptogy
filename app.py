from flask import Flask, jsonify, request, make_response
from flask.helpers import send_from_directory
from flask_cors import CORS
import logging
import cryptogy
from cryptogy.hill_cipher import HillCipher, HillCryptAnalizer
from cryptogy.stream_ciphers import AutokeyCipher, AutokeyCryptAnalizer, StreamCipher
import utils
import json

logging.basicConfig(filename='app.log', filemode='w', format='%(name)s - %(levelname)s - %(message)s')

app = Flask(__name__)
cors = CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'

@app.route('/<path:path>', methods=['GET'])
def static_proxy(path):
  return send_from_directory('./static2', path)

# Main page.
@app.route('/', methods = ["GET"])
def root():
    """
    Return the frontend of the application.
    """
    return send_from_directory("./static2", 'index.html')

# Main page.
@app.route('/classic', methods = ["GET"])
def classic():
    """
    Return the frontend of the application.
    """
    return send_from_directory("./static", 'index.html')

@app.route("/api/generate_random_key", methods = ["POST"])
def generate_random_key():
    data=request.get_json()
    if data == None:
        data = request.values
    try:
        cipher = utils.get_cipher(data)
    except Exception as e: 
        return jsonify("Invalid Key"), 401
    random_key = cipher.generateRandomKey()
    if isinstance(cipher, HillCipher):
        random_key = utils.format_darray(random_key)
    return jsonify({"random_key":random_key}), 200

@app.route("/api/encrypt", methods = ["POST"])
def encrypt():
    data=request.get_json()
    if data == None:
        data = request.values
    cleartext = data["cleartext"]
    key = utils.format_key(data["key"])
    cipher = utils.get_cipher(data)
 
    cipher.setKey(key)
    encode_text = cipher.encode(cleartext)
    if isinstance(cipher, AutokeyCipher):
        return jsonify({"ciphertext":encode_text[0], "key_stream": encode_text[1]}), 200
    else:
        return jsonify({"ciphertext":encode_text}), 200

@app.route("/api/decrypt", methods = ["POST"])
def decrypt():
    data=request.get_json()
    if data == None:
        data = request.values
    ciphertext = data["ciphertext"]
    cipher = utils.get_cipher(data)
    key = utils.format_key(data["key"])
    if isinstance(cipher, AutokeyCipher):
        key_stream = utils.format_key(data["keyStream"])
        cleartext = cipher.decode(key_stream, ciphertext)
    else:
        cipher.setKey(key)
        cleartext = cipher.decode(ciphertext)
    return jsonify({"cleartext":cleartext}), 200

@app.route("/api/analyze", methods = ["POST"])
def analyze():
    data=request.get_json()
    if data == None:
        data = request.values
    ciphertext = data["ciphertext"]
    analyzer = utils.get_analyzer(data)
    try:
        if isinstance(analyzer, AutokeyCryptAnalizer):
            cleartext = data["cleartext"]
            results = analyzer.breakCipher(cleartext, ciphertext)
        elif isinstance(analyzer, HillCryptAnalizer):
            cleartext = data["cleartext"]
            numPartitions = data["numPartitions"]
            results = analyzer.breakCipher(ciphertext, cleartext, numPartitions)
        else:
            results = analyzer.breakCipher(ciphertext)
    except Exception as e: 
        return jsonify(str(e)), 404
    return jsonify({"cleartext":results}), 200



if __name__ == '__main__':
    app.run(debug = False)