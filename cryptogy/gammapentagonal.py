from .cipher import Cipher
import random


class GammaPentagonalCipher(Cipher):

    with open("cryptogy/gammapentagonalgraph.txt", "r") as f:
        data = f.read()
    points = eval(data)

    """
    Unused: Graph is hardcoded now.

    @staticmethod
    def generateMatrix(h = 50, w = 50):
        # Inicializacion de Diccionarios
        points = {(0,0):[]}
        originpoints = [(0,0)]
        # Iterar por anchura.
        for x in range(w):
            # Crear lista temporal para actualizar puntos de origen.
            pointsnew = []
            # Iterar por los puntos de origen. (Aquellos puntos de los cuales deben comenzar nuevas ramas.)
            for point in originpoints:
                j = point[1]
                # Iterar por altura.
                for i in range(1, h):
                    # Actualizar diccionario de puntos.
                    if (point[0] + i, j) in points:
                        if (point[0] + i - 1, j - i + 1) not in points[(point[0] + i, j)]:
                            points[(point[0] + i, j)].append((point[0] + i - 1, j - i + 1))
                    else:
                        points[(point[0] + i, j)] = [(point[0]+i-1, j-i+1)]
                    # Si el punto es de origen, agregarlo.
                    if point[0] / 2 == point[1] and (point[0] + i, j) not in originpoints:
                        pointsnew.append((point[0] + i - 1, j - i + 1))
                    j += i
            originpoints = pointsnew[1:]
        return points
    """

    @staticmethod
    def shiftEncrypt(text: str, key: int):
        """
        Cifrado de desplazamiento simple para caracteres.
        """
        return chr(((ord(text.lower()) - 97 + key) % 26) + 65)

    @staticmethod
    def getRouteKey(Xi, Yi, coord):
        a, b = coord
        coord = (a - Xi, b - Yi)

        if coord in GammaPentagonalCipher.points:
            return len(GammaPentagonalCipher.points[coord])
        else:
            return 0

    @staticmethod
    def generateDicts(key):
        Xi, Yi = key[:2]
        perm = key[2:]

        ABC = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        # Primero desplazamos por la permutacion, y luego desplazamos por el numero de trayectorias.
        dicts = [
            [
                GammaPentagonalCipher.shiftEncrypt(
                    GammaPentagonalCipher.shiftEncrypt(ABC[l], perm[k]),
                    GammaPentagonalCipher.getRouteKey(Xi, Yi, (k, l)),
                )
                for l in range(26)
            ]
            for k in range(len(perm))
        ]
        return dicts

    def __init__(self, key=None):
        super().__init__()
        self.key = self.iniKey(key)
        self.dicts = GammaPentagonalCipher.generateDicts(self.key)

    def validKey(self, key):
        if len(key) <= 3:
            return False
        if all((0 <= x and x <= 25) for x in key[2:]):
            return True
        return False

    def generateRandomKey(self):
        key = list()
        for i in range(2):
            key.append(random.randint(-25, 25))
        for i in range(random.randint(5, 15)):
            rand_number = random.randint(0, 25)
            key.append(rand_number)
        return key

    def encode(self, cleartext: str):
        perm = self.key[2:]
        ciphertext = ""
        x = 0
        for l in cleartext:
            xi = x
            while self.dicts[x // 26][x % 26] != l.upper():
                x = (x + 1) % (26 * len(perm))
                if x == xi:  # Puede suceder que una letra no este en los diccionarios
                    return False
            ciphertext += "(" + str(x // 26) + ", " + str(x % 26) + ");"
        return ciphertext[:-1]

    def decode(self, ciphertext):
        cleartext = ""
        for x in ciphertext.split(";"):
            a, b = x[1:-1].split(", ")
            cleartext += self.dicts[int(a)][int(b)]
        return cleartext


if __name__ == "__main__":

    cleartext = "thealmondtree"
    cipher = GammaPentagonalCipher()
    print("cleartext: ")
    print(cleartext)
    print(cipher.encode(cleartext))

    ciphertext = cipher.encode(cleartext)
    print("ciphertext: ")
    print(ciphertext)
    print(cipher.decode(ciphertext))
