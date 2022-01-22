from flask import Flask, jsonify, request, make_response, send_file
from flask.helpers import send_from_directory
#from cryptogy.gammapentagonal import GammaPentagonalCipher
from flask_cors import CORS
import logging
import cryptogy
from cryptogy.hill_cipher import HillCipher, HillCryptAnalizer
from cryptogy.stream_ciphers import AutokeyCipher, AutokeyCryptAnalizer, StreamCipher
import cryptogy.des
from cryptogy.des import SDESCipher, DESCipher, TripleDESCipher
import cryptogy.aes
from cryptogy.aes import AESCipher
import utils
from base64 import encodebytes
import io
from PIL import Image
from utils import images_key
import numpy as np
import os
import gc

logging.basicConfig(
    filename="app.log", filemode="w", format="%(name)s - %(levelname)s - %(message)s"
)

app = Flask(__name__)
cors = CORS(app)
app.config["CORS_HEADERS"] = "Content-Type"

def get_response_image(image_path):
    pil_img = Image.open(image_path, mode="r")  # reads the PIL image
    byte_arr = io.BytesIO()
    pil_img.save(byte_arr, format="PNG")  # convert the PIL image to byte array
    encoded_img = encodebytes(byte_arr.getvalue()).decode("ascii")  # encode as base64
    return encoded_img

@app.route("/<path:path>", methods=["GET"])
def static_proxy(path):
    gc.collect()
    return send_from_directory("./static", path)

# Main page.
@app.route("/", methods=["GET"])
def root():
    """
    Return the frontend of the application.
    """
    gc.collect()
    return send_from_directory("./static", "index.html")

# Main page.
@app.route("/classic", methods=["GET"])
def classic():
    """
    Return the frontend of the application.
    """
    gc.collect()
    return send_from_directory("./static", "index.html")


# Main page.
@app.route("/block", methods=["GET"])
def block():
    """
    Return the frontend of the application.
    """
    gc.collect()
    return send_from_directory("./static", "index.html")


# Main page.
@app.route("/gamma-pentagonal", methods=["GET"])
def gamma_pentagonal():
    """
    Return the frontend of the application.
    """
    gc.collect()
    return send_from_directory("./static", "index.html")

@app.route("/api/generate_random_key", methods=["POST"])
def generate_random_key():
    
    data = request.get_json()
    if data == None:
        data = request.values
    cipher = utils.get_cipher(data)
    random_key = cipher.generateRandomKey()
    #print(random_key)
    if isinstance(cipher, HillCipher):
        random_key = utils.format_darray(random_key)
    elif (
        isinstance(cipher, SDESCipher)
        or isinstance(cipher, DESCipher)
        or isinstance(cipher, TripleDESCipher)
    ):
        random_key = utils.format_list(random_key)
    elif isinstance(cipher, AESCipher):
        random_key = random_key.hex()
    gc.collect()
    return jsonify({"random_key": random_key}), 200


@app.route("/api/encrypt", methods=["POST"])
def encrypt():
    data = request.get_json()
    if data == None:
        data = request.values
    cleartext = data["cleartext"].lower().replace(" ", "")

    if data["cipher"] == "aes":
        key = bytes.fromhex(data["key"])
    else:
        key = utils.format_key(data["key"])
    cipher = utils.get_cipher(data)
    cipher.setKey(key)

    if data["cipher"] not in ["aes", "sdes", "des"]:
        encode_text = cipher.encode(cleartext)
    elif data["cipher"] in ["sdes", "des"]:
        if data["initialPermutation"] != "":
            iv = utils.format_str_to_list(data["initialPermutation"])
            #print(iv)
            cipher.setInitialPermutation(iv)
        encode_text = cipher.encode(cleartext)
    else:
        encryptionMode = data["encryptionMode"]
        iv = bytes.fromhex(data["initialPermutation"])
        encode_text = cryptogy.aes.encrypt_text(key, iv, encryptionMode, cleartext)

    if isinstance(cipher, AutokeyCipher):
        gc.collect()
        return (
            jsonify({"ciphertext": encode_text[0], "key_stream": encode_text[1]}),
            200,
        )
    elif (
        isinstance(cipher, SDESCipher)
        or isinstance(cipher, DESCipher)
        or isinstance(cipher, TripleDESCipher)
    ):
        # print("Encrypt schedule: ")
        # print(encode_text[1])
        string = ""
        for list_ in encode_text[2]:  # schedule
            string += utils.format_list(list_) + ";"
        gc.collect()
        return jsonify(
            {
                "ciphertext": encode_text[0],
                "permutation": utils.format_list(encode_text[1]),
                "schedule": string,
            }
        )

    elif isinstance(cipher, AESCipher):
        ciphertext = encode_text[0].hex()
        iv = encode_text[1].hex()
        gc.collect()
        return jsonify({"ciphertext": ciphertext, "initialPermutation": iv}), 200
    else:
        gc.collect()
        return jsonify({"ciphertext": encode_text}), 200


@app.route("/api/decrypt", methods=["POST"])
def decrypt():
    data = request.get_json()
    if data == None:
        data = request.values
    ciphertext = data["ciphertext"]
    cipher = utils.get_cipher(data)

    if data["cipher"] == "aes":
        ciphertext = bytes.fromhex(data["ciphertext"])
        key = bytes.fromhex(data["key"])
    else:
        key = utils.format_key(data["key"])

    if isinstance(cipher, AutokeyCipher):
        key_stream = utils.format_key(data["keyStream"])
        cleartext = cipher.decode(key_stream, ciphertext)

    elif (
        isinstance(cipher, SDESCipher)
        or isinstance(cipher, DESCipher)
        or isinstance(cipher, TripleDESCipher)
    ):
        permutation = utils.format_key(data["initialPermutation"], return_np=False)
        schedule = utils.format_key(data["schedule"], return_np=False)
        encryptionMode = data["encryptionMode"]
        cipher.setEncryptionMode(encryptionMode)
        cleartext = cipher.decode(permutation, schedule, ciphertext)[0]

    elif isinstance(cipher, AESCipher):
        cipher.setKey(key)
        encryptionMode = data["encryptionMode"]
        iv = bytes.fromhex(data["initialPermutation"])
        cleartext = cryptogy.aes.decrypt_text(key, iv, encryptionMode, ciphertext)
        cleartext = cleartext.decode("utf-8")
    else:
        cipher.setKey(key)
        cleartext = cipher.decode(ciphertext)
    gc.collect()
    return jsonify({"cleartext": cleartext}), 200


@app.route("/api/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    if data == None:
        data = request.values
    ciphertext = data["ciphertext"]
    analyzer = utils.get_analyzer(data)
    if isinstance(analyzer, AutokeyCryptAnalizer):
        cleartext = data["cleartext"]
        try:
            results = analyzer.breakCipher(cleartext, ciphertext)
        except Exception as e:
            #print(str(e))
            gc.collect()
            return jsonify({"error": str(e)}), 400
    elif isinstance(analyzer, HillCryptAnalizer):
        cleartext = data["cleartext"]
        numPartitions = int(data["numPartitions"])
        try:
            results = analyzer.breakCipher(ciphertext, cleartext, numPartitions)
        except Exception as e:
            gc.collect()
            return jsonify({"error": str(e)}), 400
    else:
        try:
            results = analyzer.breakCipher(ciphertext)
        except Exception as e:
            gc.collect()
            return jsonify({"error": str(e)}), 400
    gc.collect()
    return jsonify({"cleartext": results}), 200


@app.route("/api/encrypt_image", methods=["POST", "GET"])
def encrypt_image():
    #print("ENCRYPT IMAGE")
    from utils import images_key

    data = request.values
    cipher = data["cipher"]
    img = request.files.getlist("files")[0]
    img.save("./images/raw_img.png")

    if cipher == "hill" or cipher == "permutation":
        img = HillCipher.imagToMat(img, resize=32)
        cipher = HillCipher(32, key=images_key, force_key=True)
        new_img = cipher.encode_image(img)
        new_img.save("./images/encrypt_temp.png")
        file = send_from_directory(
            "./images",
            mimetype="image/png",
            path="encrypt_temp.png",
            as_attachment=False,
            max_age=0,
        )
    elif cipher == "aes":
        # key = bytes.fromhex(data["key"])
        # iv = bytes.fromhex(data["initialPermutation"])
        key = b"Sixteen byte key"
        iv = b"0000000000000000"

        encryptionMode = data["encryptionMode"]
        route = "./images/raw_img.png"
        res = cryptogy.aes.encrypt_image(
            key, iv, encryptionMode, route, filename="./images/encrypt_temp.png"
        )
        file = send_from_directory(
            "./images",
            mimetype="image/jpg",
            path="encrypt_temp.png",
            as_attachment=False,
            max_age=0,
        )
    elif cipher == "des" or "sdes" or "3des":
        # key = b"Sixteen byte key"
        # iv = b"0000000000000000"

        key = b"\x97t\x84\xdb \x8b\xb2b"
        iv = b"Uh:d2HqF"

        encryptionMode = data["encryptionMode"]
        route = "./images/raw_img.png"
        res = cryptogy.des.encrypt_image(
            key, iv, encryptionMode, route, filename="./images/encrypt_temp.png"
        )
        file = send_from_directory(
            "./images",
            mimetype="image/jpg",
            path="encrypt_temp.png",
            as_attachment=False,
            max_age=0,
        )
    gc.collect()
    return file


@app.route("/api/decrypt_image", methods=["POST", "GET"])
def decrypt_image():
    from utils import images_inv_key

    data = request.values
    #print("DATAA DECRYPT!!")
    #print(data)
    cipher = data["cipher"]
    # img = request.files.getlist("files")[0]
    # image = "./images/encrypt_temp.png"
    img = request.files.getlist("files")[0]
    img.save("./images/encrypted_raw_img.png")

    # img = open(image, "rb")

    if cipher == "hill" or cipher == "permutation":
        img = HillCipher.imagToMat(img, resize=32)
        prev = Image.fromarray(img)
        prev.save("./images/previous_encrypt.png")
        cipher = HillCipher(32, key=images_key, force_key=True)
        new_img = cipher.decode_image(img, key_inv=images_inv_key)
        new_img = new_img.convert("L")
        new_img.save("./images/decrypt_temp.png")
        file = send_from_directory(
            "./images",
            mimetype="image/jpg",
            path="decrypt_temp.png",
            as_attachment=False,
            max_age=0,
        )
    elif cipher == "aes":
        # key = bytes.fromhex(data["key"])
        # iv = bytes.fromhex(data["initialPermutation"])
        key = b"Sixteen byte key"
        iv = b"0000000000000000"
        encryptionMode = data["encryptionMode"]
        route = "./images/encrypted_raw_img.png"
        res = cryptogy.aes.decrypt_image(
            key, iv, encryptionMode, route, filename="./images/decrypt_temp.png"
        )
        gc.collect()
        file = send_from_directory(
            "./images",
            mimetype="image/jpg",
            path="decrypt_temp.png",
            as_attachment=False,
            max_age=0,
        )
    elif cipher == "des" or "sdes" or "3des":
        # key = b"Sixteen byte key"
        # iv = b"0000000000000000"
        key = b"\x97t\x84\xdb \x8b\xb2b"
        iv = b"Uh:d2HqF"
        encryptionMode = data["encryptionMode"]
        route = "./images/encrypted_raw_img.png"
        res = cryptogy.des.decrypt_image(
            key, iv, encryptionMode, route, filename="./images/decrypt_temp.png"
        )
        gc.collect()
        file = send_from_directory(
            "./images",
            mimetype="image/jpg",
            path="decrypt_temp.png",
            as_attachment=False,
            max_age=0,
        )
    gc.collect()
    return file


@app.route("/api/change_graph", methods=["POST"])
def change_graph():
    #print("1234")
    data = request.get_json()
    if data == None:
        data = request.values
    cipher = utils.get_cipher(data)
    cipher.changeGraph()
    gc.collect()
    return jsonify({"message": "ok"})


@app.route("/api/show_graph", methods=["POST", "GET"])
def show_graph():
    data = request.values
    key = data["key"]
    res = cryptogy.gammapentagonal.showGraph(key, filename="./images/graph_temp.png")
    file = send_from_directory(
        "./images",
        mimetype="image/jpg",
        path="graph_temp.png",
        as_attachment=False,
        max_age=0,
    )
    gc.collect()
    return file

if __name__ == "__main__":
    app.run(port=5000, debug=False)