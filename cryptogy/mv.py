from .cipher import Cipher
from dataclasses import dataclass


@dataclass
class Point:
    x: int
    y: int


class MVCipher(Cipher):
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
        for i in range(self.p - 1):
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
        c = list(map(lambda x: int(x), c.split(",")))
        x = Point(c[0], c[1])
        y = Point(c[2], c[3])
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

