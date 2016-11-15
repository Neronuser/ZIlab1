import socket
import zlib
import struct
from getpass import getpass
from Crypto.Cipher import AES


def padd(text):
    return text.ljust(12, "0")


def unpadd(text):
    return text.strip('0')


def toSigned32(n):
    n &= 0xffffffff
    return n | (-(n & 0x80000000))


def _lazysecret(secret, blocksize=32, padding='}'):
    if not len(secret) in (16, 24, 32):
        return secret + (blocksize - len(secret)) * padding
    return secret


def encrypt(plaintext, secret, lazy=True, checksum=True):
    secret = _lazysecret(secret) if lazy else secret
    encobj = AES.new(secret, AES.MODE_ECB)

    if checksum:
        crc = zlib.crc32(plaintext) & 0xffffffff
        crc = toSigned32(crc)
        smt = struct.pack("i", crc)
        plaintext += smt

    return encobj.encrypt(plaintext)


def decrypt(ciphertext, secret, lazy=True, checksum=True):
    secret = _lazysecret(secret) if lazy else secret
    encobj = AES.new(secret, AES.MODE_ECB)
    plaintext = encobj.decrypt(ciphertext)

    if checksum:
        crc, plaintext = (plaintext[-4:], plaintext[:-4])
        check_crc = zlib.crc32(plaintext)
        check_crc = toSigned32(check_crc)
        smt = struct.pack("i", check_crc)
        if not crc == smt:
            print("Wrong Checksum")

    return plaintext


def brute_force(p, g, A, B):
    for i in range(1, p):
        candidate = (g ** i) % p
        if candidate == A:
            return (B ** i) % p
        if candidate == B:
            return (A ** i) % p


sharedPrime = 23  # p
sharedBase = 4  # g
clientSecret = 6  # a
print("p " + str(sharedPrime))
print("g " + str(sharedBase))
print("clientSecret(a)" + str(clientSecret))
A = str((sharedBase ** clientSecret) % sharedPrime)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server_address = ('localhost', 10002)
print('connecting to %s port %s' % server_address)
sock.connect(server_address)


chat()


def brute_force_and_connect():
    # TODO: get following values from Wireshark and hardcode here
    A = 8
    B = 19
    
    shared_secret = brute_force(sharedPrime, sharedBase, A, B)
    print("Found shared secret: %s" % shared_secret)
    
    padded_shared_secret = padd(str(shared_secret))
    encrypted_padded_shared_secret = encrypt(bytes(padded_shared_secret, "UTF-8"), str(shared_secret))
    sock.sendall(encrypted_padded_shared_secret)


def chat():
    try:
        print(bytes(A, "UTF-8"))
        sock.sendall(bytes(A, "UTF-8"))

        B = sock.recv(100)
        B = int(B)
        print('received "%s"' % B)

        clientSharedSecret = (B ** clientSecret) % sharedPrime
        print("Secret: %s" % clientSharedSecret)

        print("Handshake ended")

        paddedClientSharedSecret = padd(str(clientSharedSecret))
        encryptedPaddedClientSharedSecret = encrypt(bytes(paddedClientSharedSecret, "UTF-8"), str(clientSharedSecret))
        sock.sendall(encryptedPaddedClientSharedSecret)

        while True:
            login = input("Input your login\n")
            login = padd(login)
            encrypted_login = encrypt(bytes(login, "UTF-8"), str(clientSharedSecret))
            sock.sendall(encrypted_login)

            print(encrypted_login)

            response = decrypt(sock.recv(100), str(clientSharedSecret))
            if response.decode('ascii') == padd("Wrong login"):
                print("Wrong login, try again")
                continue

            while True:
                # password = input("Input your password\n")
                password = getpass("Input your password\n")
                password = padd(password)
                encrypted_pass = encrypt(bytes(password, "UTF-8"), str(clientSharedSecret))
                sock.sendall(encrypted_pass)

                response = decrypt(sock.recv(100), str(clientSharedSecret))
                if response.decode('ascii') == padd("Wrong pass"):
                    print("Wrong password")
                    continue
                elif response.decode('ascii') == padd("Successful"):
                    print("Success")
                else:
                    exit()
                break

            while True:
                message1 = input("Message:\n")
                message = padd(message1)
                encrypted_message = encrypt(bytes(message, "UTF-8"), str(clientSharedSecret))
                sock.sendall(encrypted_message)
                if message1 == "q":
                    break
                encrypted_response = sock.recv(100)
                response = decrypt(encrypted_response, str(clientSharedSecret))
                print(unpadd(response.decode('ascii')))
            break

    finally:
        print('closing socket')
        sock.close()
