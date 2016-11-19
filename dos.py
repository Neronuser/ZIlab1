import socket


def attack():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('localhost', 10002))
    s.send(b"abc")
    s.close()


for i in range(1, 10000000):
    attack()
