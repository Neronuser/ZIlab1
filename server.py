import socket
import zlib
import struct
from Crypto.Cipher import AES

login2password = {
    "abc": "best",
    "bca": "worst",
    "cab": "trash"
}


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

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(('localhost', 10002))

sock.listen(1)

sharedPrime = 23    # p
sharedBase = 4      # g
serverSecret = 15      # b

print("p " + str(sharedPrime))
print("g " + str(sharedBase))
print("serverSecret(b) " + str(serverSecret))

B = (sharedBase ** serverSecret) % sharedPrime

paddedDict = {padd(login): padd(password) for login, password in login2password.items()}

while True:
    print('waiting for a connection')
    connection, client_address = sock.accept()

    try:
        print('connection from', client_address)

        try:
            A = int(connection.recv(100))
        except:
            continue

        serverSharedSecret = (A**serverSecret) % sharedPrime
        print('received "%s"' % A)
        print("secret: %s" % serverSharedSecret)
        connection.sendall(bytes(str(B), "UTF-8"))

        encryptedClientSharedSecret = connection.recv(100)
        try:
            decryptedClientSharedSecret = decrypt(encryptedClientSharedSecret, str(serverSharedSecret))
            unpaddedClientSharedSecret = unpadd(decryptedClientSharedSecret.decode('ascii'))
        except:
            print("Could not decode client shared secret")
            connection.close()

        print("Handshake ended")

        while True:
            encrypted_login = connection.recv(100)
            login = decrypt(encrypted_login, str(serverSharedSecret))
            print(unpadd(login.decode('ascii')))
            if login.decode('ascii') not in paddedDict.keys():
                connection.sendall(encrypt(bytes(padd("Wrong login"), "UTF-8"), str(serverSharedSecret)))
                continue
            else:
                connection.sendall(encrypt(bytes(padd("Pass"), "UTF-8"), str(serverSharedSecret)))
            for i in range(3):
                encrypted_password = connection.recv(100)
                password = decrypt(encrypted_password, str(serverSharedSecret))
                print(unpadd(password.decode('ascii')))
                if password.decode('ascii') != paddedDict[login.decode('ascii')]:
                    if i == 2:
                        print("Intruder detected")
                        connection.close()
                        exit()
                    else:
                        connection.sendall(encrypt(bytes(padd("Wrong pass"), "UTF-8"), str(serverSharedSecret)))
                    continue
                print("Successful login")
                connection.sendall(encrypt(bytes(padd("Successful"), "UTF-8"), str(serverSharedSecret)))
                break
            break

        while True:
            encrypted_message = connection.recv(16)
            message = decrypt(encrypted_message, str(serverSharedSecret))
            print(unpadd(message.decode('ascii')))
            if unpadd(message.decode('ascii')) == "q":
                break
            response = input("Response message:\n")
            response = padd(response)
            encrypted_response = encrypt(bytes(response, "UTF-8"), str(serverSharedSecret))
            connection.sendall(encrypted_response)
        break

    finally:
        connection.close()
