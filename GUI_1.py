import tkinter as tk
import random, sys, os
import pyperclip

HEIGHT = 1000
WIDTH = 1000

DEFAULT_BLOCK_SIZE = 128
BYTE_SIZE = 256

import random


def rabinMiller(num):
    s = num - 1
    t = 0
    while s % 2 == 0:

        s = s // 2
        t += 1

    for trials in range(5):
        a = random.randrange(2, num - 1)
        v = pow(a, s, num)
        if v != 1:
            i = 0
            while v != (num - 1):
                if i == t - 1:
                    return False
                else:
                    i = i + 1
                    v = (v ** 2) % num
    return True


def isPrime(num):

    if (num < 2):
        return False

    lowPrimes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997]

    if num in lowPrimes:
        return True

    for prime in lowPrimes:
        if (num % prime == 0):
            return False

    return rabinMiller(num)


def generateLargePrime(keysize=1024):
    while True:
        num = random.randrange(2**(keysize-1), 2**(keysize))
        if isPrime(num):
            return num

def gcd(a, b):

    while a != 0:
        a, b = b % a, a
    return b


def findModInverse(a, m):
    if gcd(a, m) != 1:
        return None
    u1, u2, u3 = 1, 0, a
    v1, v2, v3 = 0, 1, m
    while v3 != 0:
        q = u3 // v3
        v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
    return u1 % m

def CreateKeys(entry1):

    print('Making key files...')
    makeKeyFiles(entry1, 1024)
    print('Key files made.')





def makeKeyFiles(name: object, keySize: object) -> object:

    if os.path.exists('%s_pubkey.txt' % (name)) or os.path.exists('%s_privkey.txt' % (name)):
        sys.exit('WARNING: The file %s_pubkey.txt or %s_privkey.txt already exists! Use a different name or delete these files and rerun this program.' % (name, name))

    publicKey, privateKey = generateKey(keySize)

    print()
    print('The public key is a %s and a %s digit number.' % (len(str(publicKey[0])), len(str(publicKey[1]))))
    print('Writing public key to file %s_pubkey.txt...' % (name))
    fo = open('%s_pubkey.txt' % (name), 'w')
    fo.write('%s,%s,%s' % (keySize, publicKey[0], publicKey[1]))
    fo.close()


    print()
    print('The private key is a %s and a %s digit number.' % (len(str(publicKey[0])), len(str(publicKey[1]))))
    print('Writing private key to file %s_privkey.txt...' % (name))
    fo = open('%s_privkey.txt' % (name), 'w')
    fo.write('%s,%s,%s' % (keySize, privateKey[0], privateKey[1]))
    fo.close()


def generateKey(keySize):
    print('Generating p prime...')
    p = generateLargePrime(keySize)
    print('Generating q prime...')
    q = generateLargePrime(keySize)
    n = p * q

    print('Generating e that is relatively prime to (p-1)*(q-1)...')
    while True:
        e = random.randrange(2 ** (keySize - 1), 2 ** (keySize))
        if gcd(e, (p - 1) * (q - 1)) == 1:
            break

    print('Calculating d that is mod inverse of e...')
    d = findModInverse(e, (p - 1) * (q - 1))
    global publicKey
    global privateKey
    publicKey = (n, e)
    privateKey = (n, d)
    print('Public key:', publicKey)
    print('Private key:', privateKey)
    return (publicKey, privateKey)

def mainEncrypt():

    filename = 'encrypted_file.txt'
    mode = ('encrypt')

    if mode == 'encrypt':
        message = (entry2)
        global PubKeyFilename
        pubKeyFilename = (entry1) + ('_pubkey.txt')
        print('Encrypting and writing to %s...' % (filename))
        global encryptedText
        encryptedText = encryptAndWriteToFile(filename, pubKeyFilename, message)

        print('Encrypted text:')
        print(encryptedText)



def mainDecrypt():

    filename = 'encrypted_file.txt'
    mode = ('decrypt')

    if mode == 'decrypt':
        privKeyFilename = (entry3) + ('_privkey.txt')
        print('Reading from %s and decrypting...' % (filename))
        global decryptedText
        decryptedText = readFromFileAndDecrypt(filename, privKeyFilename)

        print('Decrypted text:')
        print(decryptedText)

def getBlocksFromText(message, blockSize=DEFAULT_BLOCK_SIZE):


    messageBytes = message.encode('ascii')
    blockInts = []
    for blockStart in range(0, len(messageBytes), blockSize):

        blockInt = 0
        for i in range(blockStart, min(blockStart + blockSize, len(messageBytes))):
            blockInt += messageBytes[i] * (BYTE_SIZE ** (i % blockSize))
        blockInts.append(blockInt)
    return blockInts


def getTextFromBlocks(blockInts, messageLength, blockSize=DEFAULT_BLOCK_SIZE):

    message = []
    for blockInt in blockInts:
        blockMessage = []
        for i in range(blockSize - 1, -1, -1):
            if len(message) + i < messageLength:

                asciiNumber = blockInt // (BYTE_SIZE ** i)
                blockInt = blockInt % (BYTE_SIZE ** i)
                blockMessage.insert(0, chr(asciiNumber))
        message.extend(blockMessage)
    return ''.join(message)


def encryptMessage(message, key, blockSize=DEFAULT_BLOCK_SIZE):

    encryptedBlocks = []
    n, e = key

    for block in getBlocksFromText(message, blockSize):

        encryptedBlocks.append(pow(block, e, n))
    return encryptedBlocks


def decryptMessage(encryptedBlocks, messageLength, key, blockSize=DEFAULT_BLOCK_SIZE):

    decryptedBlocks = []
    n, d = key
    for block in encryptedBlocks:

        decryptedBlocks.append(pow(block, d, n))
    return getTextFromBlocks(decryptedBlocks, messageLength, blockSize)


def readKeyFile(keyFilename):

    fo = open(keyFilename)
    content = fo.read()
    fo.close()
    keySize, n, EorD = content.split(',')
    return (int(keySize), int(n), int(EorD))


def encryptAndWriteToFile(messageFilename, keyFilename, message, blockSize=DEFAULT_BLOCK_SIZE):

    keySize, n, e = readKeyFile(keyFilename)

    if keySize < blockSize * 8:
        sys.exit('ERROR: Block size is %s bits and key size is %s bits. The RSA cipher requires the block size to be equal to or greater than the key size. Either decrease the block size or use different keys.' % (blockSize * 8, keySize))



    encryptedBlocks = encryptMessage(message, (n, e), blockSize)

    for i in range(len(encryptedBlocks)):
        encryptedBlocks[i] = str(encryptedBlocks[i])
    encryptedContent = ','.join(encryptedBlocks)

    encryptedContent = '%s_%s_%s' % (len(message), blockSize, encryptedContent)
    fo = open(messageFilename, 'w')
    fo.write(encryptedContent)
    fo.close()
    return encryptedContent


def readFromFileAndDecrypt(messageFilename, keyFilename):

    keySize, n, d = readKeyFile(keyFilename)


    fo = open(messageFilename)
    content = fo.read()
    messageLength, blockSize, encryptedMessage = content.split('_')
    messageLength = int(messageLength)
    blockSize = int(blockSize)

    if keySize < blockSize * 8:
        sys.exit('ERROR: Block size is %s bits and key size is %s bits. The RSA cipher requires the block size to be equal to or greater than the key size. Did you specify the correct key file and encrypted file?' % (blockSize * 8, keySize))

    encryptedBlocks = []
    for block in encryptedMessage.split(','):
        encryptedBlocks.append(int(block))

    return decryptMessage(encryptedBlocks, messageLength, (n, d), blockSize)


def define1():
    global entry1
    entry1 = entry1.get()

def define2():
    global entry2
    entry2 = entry2.get()

def define3():
    global entry3
    entry3 = entry3.get()

def define4():
    global entry4
    entry4 = entry4.get()


def Encrypt():
    CreateKeys(entry1)
    mainEncrypt()


def clicked1():

    pyperclip.copy(encryptedText)
    label1.configure(text=('The private key is a %s and a %s digit number.' % (len(str(publicKey[0])), len(str(publicKey[1])))) + ('\nThe private key is a %s and a %s digit number.\nKey files made and saved as:')% (len(str(publicKey[0])), len(str(publicKey[1]))) + ("\n* %s")% ((str(entry1) + ('_privkey.txt'))) + ("\n* %s")% ((str(entry1) + ('_pubkey.txt')))+ ("\n* encrypted_file.txt"))

def clicked2():
    pyperclip.copy(decryptedText)
    label2.configure(text=('message: %s'%(decryptedText)))








root = tk.Tk()

root.title("RSA Kryptographie")

canvas = tk.Canvas(root, height=HEIGHT, width=WIDTH)
canvas.pack()

background_image = tk.PhotoImage(file="HINTERGRUND.png")
background_label = tk.Label(root, image=background_image)
background_label.place(relwidth=1, relheight=1)



titleframe1 = tk.Frame(root, bg="black", bd=5)
titleframe1.place(relwidth=0.75, relheight=0.05, relx=0.5, rely=0.025, anchor="n")

frame1 = tk.Frame(root, bg="black", bd=5)
frame1.place(relwidth=0.75, relheight=0.075, relx=0.5, rely=0.1, anchor="n")

frame2 = tk.Frame(root, bg="black", bd=5)
frame2.place(relwidth=0.75, relheight=0.075, relx=0.5, rely=0.175, anchor="n")

frame3 = tk.Frame(root, bg="black", bd=5)
frame3.place(relwidth=0.75, relheight=0.075, relx=0.5, rely=0.25, anchor="n")


lblframe1 = tk.Frame(root, bg="black", bd=5)
lblframe1.place(relwidth=0.75, relheight=0.15, relx=0.5, rely=0.325, anchor="n")

titleframe2 = tk.Frame(root, bg="black", bd=5)
titleframe2.place(relwidth=0.75, relheight=0.05, relx=0.5, rely=0.5, anchor="n")

frame4 = tk.Frame(root, bg="black", bd=5)
frame4.place(relwidth=0.75, relheight=0.075, relx=0.5, rely=0.575, anchor="n")

frame5 = tk.Frame(root, bg="black", bd=5)
frame5.place(relwidth=0.75, relheight=0.075, relx=0.5, rely=0.65, anchor="n")

frame6 = tk.Frame(root, bg="black", bd=5)
frame6.place(relwidth=0.75, relheight=0.075, relx=0.5, rely=0.725, anchor="n")


lblframe2 = tk.Frame(root, bg="black", bd=5)
lblframe2.place(relwidth=0.75, relheight=0.15, relx=0.5, rely=0.8, anchor="n")




entry1 = tk.Entry(frame1,font=40)
entry1.place(relwidth=0.65, relheight=1,)

entry2 = tk.Entry(frame2,font=40)
entry2.place(relwidth=0.65, relheight=1,)



entry3 = tk.Entry(frame4,font=40)
entry3.place(relwidth=0.65, relheight=1,)

entry4 = tk.Entry(frame5,font=40)
entry4.place(relwidth=0.65, relheight=1,)




button1 = tk.Button(frame1, text="file name",fg="#DF0174", font=40,command=lambda: define1())
button1.place(relwidth=0.3, relheight=1, relx=0.7,)

button2 = tk.Button(frame2, text="message",fg="#DF0174", font=40,command=lambda: define2())
button2.place(relwidth=0.3, relheight=1, relx=0.7,)

button3 = tk.Button(frame3, text="encrypt",fg="#DF0174", font=40, command=lambda: (Encrypt(), clicked1()))
button3.place(relwidth=1, relheight=1,)



button4 = tk.Button(frame4, text="file name",fg="#DF0174", font=40,command=lambda: define3())
button4.place(relwidth=0.3, relheight=1, relx=0.7,)

button5 = tk.Button(frame5, text="ciphertext",fg="#DF0174", font=40,command=lambda: define4())
button5.place(relwidth=0.3, relheight=1, relx=0.7,)

button6 = tk.Button(frame6, text="decrypt",fg="#DF0174", font=40,command=lambda: (mainDecrypt(), clicked2()))
button6.place(relwidth=1, relheight=1,)








label1 = tk.Label(lblframe1, text="waiting...", bg="black", fg="white")
label1.place(relwidth=1, relheight=1)

label2 = tk.Label(lblframe2, text="waiting...", bg="black", fg="white")
label2.place(relwidth=1, relheight=1)

titlelabel1 = tk.Label(titleframe1, text="VERSCHLÜSSELUNG", bg="black", fg="white")
titlelabel1.place(relwidth=1, relheight=1)

titlelabel2 = tk.Label(titleframe2, text="ENTSCHLÜSSELUNG", bg="black", fg="white")
titlelabel2.place(relwidth=1, relheight=1)


root.mainloop()
