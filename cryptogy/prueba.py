from PIL import Image
import numpy as np 
if __name__ == "__main__":
    from PIL import Image
    img = Image.open("hopper2.jpg") 
    img = np.asarray(img)
    print(img.shape)