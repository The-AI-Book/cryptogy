import cv2
import numpy as np
from Crypto.Cipher import AES

# https://stackoverflow.com/questions/61240967/image-encryption-using-aes-in-python
key = b'Sixteen byte key'
iv = b'0000000000000000'

# Read image to NumPy array - array shape is (300, 451, 3)
img = cv2.imread('C:\\Users\\Pablo\\Desktop\\imageEncryption\\input.png')

# Pad zero rows in case number of bytes is not a multiple of 16 (just an example - there are many options for padding)
if img.size % 16 > 0:
    row = img.shape[0]
    pad = 16 - (row % 16)  # Number of rows to pad (4 rows)
    img = np.pad(img, ((0, pad), (0, 0), (0, 0)))  # Pad rows at the bottom  - new shape is (304, 451, 3) - 411312 bytes.
    img[-1, -1, 0] = pad  # Store the pad value in the last element


img_bytes = img.tobytes()  # Convert NumPy array to sequence of bytes (411312 bytes)
print(img_bytes[:11], type(img_bytes))
enc_img_bytes = AES.new(key, AES.MODE_ECB).encrypt(img_bytes)
print(enc_img_bytes, type(enc_img_bytes))
# enc_img_bytes = AES.new(key, AES.MODE_CBC, iv).encrypt(img_bytes)  # Encrypt the array of bytes.
# Convert the encrypted buffer to NumPy array and reshape to the shape of the padded image (304, 451, 3)
enc_img = np.frombuffer(enc_img_bytes, np.uint8).reshape(img.shape)

# Save the image - Save in PNG format because PNG is lossless (JPEG format is not going to work).
cv2.imwrite('C:\\Users\\Pablo\\Desktop\\imageEncryption\\encrypted_input.png', enc_img)



# Decrypt:
################################################################################
key = b'Sixteen byte key'
iv = b'0000000000000000'

enc_img = cv2.imread('C:\\Users\\Pablo\\Desktop\\imageEncryption\\encrypted_input.png')

dec_img_bytes = AES.new(key, AES.MODE_ECB).decrypt(enc_img.tobytes())
# dec_img_bytes = AES.new(key, AES.MODE_CBC, iv).decrypt(enc_img.tobytes())

dec_img = np.frombuffer(dec_img_bytes, np.uint8).reshape(enc_img.shape)  # The shape of the encrypted and decrypted image is the same (304, 451, 3)

pad = int(dec_img[-1, -1, 0])  # Get the stored padding value

dec_img = dec_img[0:-pad, :, :].copy()  # Remove the padding rows, new shape is (300, 451, 3)

# Save the decoded image
cv2.imwrite('C:\\Users\\Pablo\\Desktop\\imageEncryption\\decrypted_input.png', dec_img)