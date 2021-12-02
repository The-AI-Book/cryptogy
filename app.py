from flask import Flask, jsonify, request, make_response, send_file
from flask.helpers import send_from_directory
from flask_cors import CORS
import logging
import cryptogy
from cryptogy.hill_cipher import HillCipher, HillCryptAnalizer
from cryptogy.stream_ciphers import AutokeyCipher, AutokeyCryptAnalizer, StreamCipher
import utils
from base64 import encodebytes
import io
from PIL import Image
from utils import images_key

logging.basicConfig(filename='app.log', filemode='w', format='%(name)s - %(levelname)s - %(message)s')

app = Flask(__name__)
cors = CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'

def get_response_image(image_path):
    pil_img = Image.open(image_path, mode='r') # reads the PIL image
    byte_arr = io.BytesIO()
    pil_img.save(byte_arr, format='PNG') # convert the PIL image to byte array
    encoded_img = encodebytes(byte_arr.getvalue()).decode('ascii') # encode as base64
    return encoded_img


@app.route('/<path:path>', methods=['GET'])
def static_proxy(path):
  return send_from_directory('./static', path)

# Main page.
@app.route('/', methods = ["GET"])
def root():
    """
    Return the frontend of the application.
    """
    return send_from_directory("./static", 'index.html')

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
    cipher = utils.get_cipher(data)
    random_key = cipher.generateRandomKey()
    if isinstance(cipher, HillCipher):
        random_key = utils.format_darray(random_key)
    return jsonify({"random_key":random_key}), 200

@app.route("/api/encrypt", methods = ["POST"])
def encrypt():
    data=request.get_json()
    if data == None:
        data = request.values
    cleartext = data["cleartext"].lower().replace(" ", "")
    key = utils.format_key(data["key"])
    cipher = utils.get_cipher(data)
    cipher.setKey(key)
    encode_text = cipher.encode(cleartext)
    if isinstance(cipher, AutokeyCipher):
        return jsonify({"ciphertext":encode_text[0], "key_stream": encode_text[1]}), 200
    else:
        return jsonify({"ciphertext":encode_text}), 200

@app.route("/api/encrypt_image", methods = ["POST", "GET"])
def encrypt_image():
    print("encrypt image!")
    img = request.files.getlist("files")[0]
    img = HillCipher.imagToMat(img, resize = 4)
    #print(img)
    cipher = HillCipher(m = 4)    
    print("trying to encode...") 
    new_img = cipher.encode_image(img)
    new_img.save("./images/temp.png")
    print("image saved!")
    #img = Image.open("./images/temp.png")
    #file_object = io.BytesIO()
    #img.save(file_object, "PNG")
    #file_object.seek(0)
    #print(file_object)
    file =  send_from_directory("./images", mimetype = "image/PNG", path = "gray2.png", as_attachment=True, max_age = 0)
    return file 

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
    if isinstance(analyzer, AutokeyCryptAnalizer):
        cleartext = data["cleartext"]
        try:
            results = analyzer.breakCipher(cleartext, ciphertext)
        except Exception as e: 
            print(str(e))
            return jsonify({"error":str(e)}), 400
    elif isinstance(analyzer, HillCryptAnalizer):
        cleartext = data["cleartext"]
        numPartitions = int(data["numPartitions"])
        #print(cleartext)
        #print(numPartitions)
        #print(ciphertext)
        try:
            results = analyzer.breakCipher(ciphertext, cleartext, numPartitions)
        except Exception as e: 
            return jsonify({"error":str(e)}), 400
    else:
        try:
            results = analyzer.breakCipher(ciphertext)
        except Exception as e: 
            return jsonify({"error":str(e)}), 400
    return jsonify({"cleartext":results}), 200



if __name__ == '__main__':
    app.run(port = 5000, debug = True)