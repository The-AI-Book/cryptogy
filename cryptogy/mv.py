from .cipher import Cipher
from dataclasses import dataclass
import random


@dataclass
class Point:
    x: int
    y: int


# robado de rsa con amor <3
first_primes_list = [
    2,
    3,
    5,
    7,
    11,
    13,
    17,
    19,
    23,
    29,
    31,
    37,
    41,
    43,
    47,
    53,
    59,
    61,
    67,
    71,
    73,
    79,
    83,
    89,
    97,
    101,
    103,
    107,
    109,
    113,
    127,
    131,
    137,
    139,
    149,
    151,
    157,
    163,
    167,
    173,
    179,
    181,
    191,
    193,
    197,
    199,
    211,
    223,
    227,
    229,
    233,
    239,
    241,
    251,
    257,
    263,
    269,
    271,
    277,
    281,
    283,
    293,
    307,
    311,
    313,
    317,
    331,
    337,
    347,
    349,
]


class MVCipher(Cipher):
    def generateRandomKey(self):
        a = random.randint(0, 100)
        b = random.randint(0, 100)
        p = random.choice(first_primes_list)
        cycle = MVCipher.getPoints(a, b, p)
        generator = random.choice(cycle)
        alpha = random.randint(0, len(cycle))
        k = random.randint(0, len(cycle))
        return (a, b, p, generator[0], generator[1], alpha, k)

    def getPoints(a, b, p):
        points = []
        for x in range(p):
            for y in range(p):
                if (y ** 2 - (x ** 3 + (a * x) + b)) % p == 0:
                    points.append((x, y))
        return points

    def __init__(self, key=None):
        super().__init__()

    def setParams(self, a: int, b: int, p: int, generator: tuple):
        self.a = a
        self.b = b
        self.p = p

        self.points = []
        self.definePoints()

        if generator in self.points:
            gx = generator[0]
            gy = generator[1]
            self.generator = Point(gx, gy)
        else:
            raise Exception("generator not in curve")

    def definePoints(self):
        for x in range(self.p):
            for y in range(self.p):
                if (y ** 2 - (x ** 3 + (self.a * x) + self.b)) % self.p == 0:
                    self.points.append((x, y))

    def add(self, p1, p2):

        if p1 == p2:
            h = ((3 * p1.x ** 2 + self.a) % self.p * pow(2 * p1.y, -1, self.p)) % self.p
        else:
            h = ((p2.y - p1.y) % self.p * pow(p2.x - p1.x, -1, self.p)) % self.p

        x3 = (h ** 2 - p1.x - p2.x) % self.p
        y3 = (h * (p1.x - x3) - p1.y) % self.p

        return Point(x3, y3)

    def generateCycle(self, generator: Point):
        cycle = [generator]
        np = self.add(generator, generator)
        cycle.append(np)
        while np.x != generator.x:
            np = self.add(np, generator)
            cycle.append(np)
        cycle.append("O")
        return cycle

    def keyGen(self, key, cycle):
        key = key % self.p
        if key == 0:
            return cycle[-1]
        return cycle[key - 1]

    def encode(self, m: tuple, a: int, k: int):
        m = Point(m[0], m[1])
        b = MVCipher.keyGen(self, a, MVCipher.generateCycle(self, self.generator))
        x = MVCipher.keyGen(self, k, MVCipher.generateCycle(self, self.generator))
        y = MVCipher.add(
            self, m, MVCipher.keyGen(self, k, MVCipher.generateCycle(self, b))
        )
        return ((x.x, x.y), (y.x, y.y))

    def decode(self, c: str, a: int):
        x = Point(c[0][0], c[0][1])
        y = Point(c[1][0], c[1][1])
        r = MVCipher.add(
            self,
            y,
            MVCipher.generateCycle(
                self, MVCipher.keyGen(self, a, MVCipher.generateCycle(self, x))
            )[-2],
        )
        return (r.x, r.y)


if __name__ == "__main__":
    a = 1
    b = 6
    p = 11
    generator = (2, 7)

    cipher = MVCipher()
    cipher.setParams(a, b, p, generator)

    message = (10, 9)
    alpha = 7
    k = 3

    e = cipher.encode(message, alpha, k)
    print("encode")
    print(e)
    print(type(e))
    print("decode")
    d = cipher.decode(e, alpha)
    print(d)

