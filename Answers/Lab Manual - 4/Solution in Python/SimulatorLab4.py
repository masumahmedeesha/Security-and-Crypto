from Crypto import Random
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_PSS
from base64 import b64encode, b64decode
import errno
from time import time
from matplotlib import pyplot as plt


def padToText(message, blockSize):
    numberOfBytesToPad = blockSize - len(message) % blockSize
    paddingStr = numberOfBytesToPad * chr(numberOfBytesToPad)
    return message + paddingStr

def padToKey(key, keyLength):
    numberOfBytesToPad = keyLength - len(key) % keyLength
    paddingStr = numberOfBytesToPad * chr(numberOfBytesToPad)
    return key + paddingStr

def unpadToText(message):
    lastCharacter = message[len(message) - 1:]
    return message[:-ord(lastCharacter)]

def unpadToKey(key):
    lastCharacter = key[len(key) - 1:]
    return key[:-ord(lastCharacter)]

def aesEncryption(blockSize, message, key, mode):
    if mode.lower() == "ecb":
        message = padToText(message, blockSize)
        cipher = AES.new(key, AES.MODE_ECB)
        encryptedText = cipher.encrypt(str.encode(message))
        # without padding, Input strings must be a multiple of 16 in length
        return b64encode(encryptedText).decode("utf-8")
    elif mode.lower() == "cfb":
        iv = Random.new().read(blockSize)
        cipher = AES.new(key, AES.MODE_CFB, iv)
        encryptedText = cipher.encrypt(str.encode(message))
        return b64encode(iv + encryptedText).decode("utf-8")
    else:
        return
        
def aesDecryption(blockSize, encryptedText, key, mode):
    encryptedText = b64decode(encryptedText)
    if mode.lower() == "ecb":
        cipher = AES.new(key, AES.MODE_ECB)
        decryptedText = cipher.decrypt(encryptedText).decode("utf-8")
        return unpadToText(decryptedText)
    elif mode.lower() == "cfb":
        iv = encryptedText[:blockSize]
        cipher = AES.new(key, AES.MODE_CFB, iv)
        decryptedText = cipher.decrypt(encryptedText[blockSize:]).decode("utf-8")
        return decryptedText
    else:
        return

def aesKeyWrite(key):
    with open('aes/aesKey.txt','w') as keyFile:
        keyFile.write(key)

def aesKeyRead():
    with open('aes/aesKey.txt', 'r') as keyFile:
        return keyFile.read()

def aesEncryptedMessage(blockSize, message, key, mode, variation):
    encryptedMessage = aesEncryption(blockSize, message, key, mode)
    print('Encrypted Text: '+str(encryptedMessage) + ' '+str(variation)+' using '+str(mode)+' mode')
    fileName = str(variation)+'-'+str(mode)+'.txt'
    with open('aes/'+fileName, 'w') as aesEncryptedResult:
        aesEncryptedResult.write(encryptedMessage)
    
def aesDecryptedMessage(blockSize, message, key, mode, variation):
    fileName = str(message)
    encryptedMessage = ''
    try:
        with open('aes/'+fileName, 'r') as readFile:
            encryptedMessage = readFile.read()
    except IOError as e:
        if e.errno != errno.ENOENT:
            raise
            
    if encryptedMessage:
        decryptedMessage = aesDecryption(blockSize, encryptedMessage, key, mode)    
        print('Decrypted Text: '+decryptedMessage + ' '+variation+' using '+mode+' mode')

    
def aes(message, key, variation, mode, typeChosen):
    blockSize = AES.block_size
    if variation.lower() == 'aes-128':
        key = padToKey(key[:16], 16)
        if typeChosen == 'e':
#            print(blockSize, message, key, mode, variation)
            aesEncryptedMessage(blockSize, message, key, mode, variation)
        else:
            aesDecryptedMessage(blockSize, message, key, mode, variation)
    elif variation.lower() == 'aes-192':
        key = padToKey(key[:24], 24)
        if typeChosen == 'e':
            aesEncryptedMessage(blockSize, message, key, mode, variation)
        else:
            aesDecryptedMessage(blockSize, message, key, mode, variation)
    else:
        key = padToKey(key[:32], 32)
        if typeChosen == 'e':
            aesEncryptedMessage(blockSize, message, key, mode, variation)
        else:
            aesDecryptedMessage(blockSize, message, key, mode, variation)

        
## RSA START
def keyGenerationAndStore(variation):
    key = RSA.generate(int(variation))
    privateKey = key.exportKey('PEM')
    privateFileName = 'privateKey'+str(variation)+'.pem'
    with open('rsa/'+privateFileName, 'wb') as privateFile:
        privateFile.write(privateKey)
    publicKey = key.publickey().exportKey('PEM')
    publicFileName = 'publicKey'+str(variation)+'.pem'
    with open('rsa/'+publicFileName,'wb') as publicFile:
        publicFile.write(publicKey)
    return privateFileName, publicFileName

def readPublicKey(variation, fileName):
    with open('rsa/'+fileName, 'r') as publicRead:
        return publicRead.read()

def readPrivateKey(variation, fileName):
    with open('rsa/'+fileName, 'r') as privateRead:
        return privateRead.read()
    
def rsaEncryption(variation, message, publicFileName):
    rsaPublicKey = RSA.importKey(readPublicKey(variation, publicFileName))
    rsaPublicKey = PKCS1_OAEP.new(rsaPublicKey)
    # encrypt() missing 1 required positional argument: 'K' error without pad
    encryptedText = rsaPublicKey.encrypt(str.encode(message))
    fName = 'rsa-'+str(variation)+'.txt'
    with open('rsa/'+fName, 'wb') as rsaFile:
        rsaFile.write(encryptedText)
    return encryptedText


def rsaDecryption(variation, fileName, privateFileName):
    encryptedText = ''
    try:
        with open('rsa/'+fileName, 'rb') as readFile:
            encryptedText = readFile.read()
    except IOError as e:
        if e.errno != errno.ENOENT:
            raise
    if encryptedText:
        rsaPrivateKey = RSA.importKey(readPrivateKey(variation, privateFileName))
        rsaPrivateKey = PKCS1_OAEP.new(rsaPrivateKey)
        return rsaPrivateKey.decrypt(encryptedText)
    else:
        return

def rsa(variation, message, typeChosen, publicFileName, privateFileName):
    if typeChosen == 'e':
        encryptedText = rsaEncryption(variation, message, publicFileName)
        print("Encrypted Text: "+str(encryptedText)+ ' using RSA-'+ str(variation))
    else:
        decryptedText = rsaDecryption(variation, message, privateFileName)
        if decryptedText:
            print("Decrypted Text from file: "+str(decryptedText)+ ' using RSA-'+ str(variation))

def readForSignature(fileName):
    content = ''
    try:
        with open('rsa-signature/'+fileName, 'r') as readFile:
            content = readFile.read()
    except IOError as e:
        if e.errno != errno.ENOENT:
            raise
    if content:
        return content
    else:
        return

def readForSignatureSig(fileName):
    content = ''
    try:
        with open('rsa-signature/'+fileName, 'rb') as readFile:
            content = readFile.read()
    except IOError as e:
        if e.errno != errno.ENOENT:
            raise
    if content:
        return content
    else:
        return
            
def rsaSignatureCreate(fileName, message, variation, privateFileName):
    hashedMessage = SHA256.new()
    hashedMessage.update(str.encode(message))
    privateKey = RSA.importKey(readPrivateKey(variation, privateFileName))
    signPrivate = PKCS1_PSS.new(privateKey)
    signature = signPrivate.sign(hashedMessage)
    fileName = fileName.split('.')[0] + ".sig"
    with open('rsa-signature/'+fileName, 'wb') as signatureFile:
        signatureFile.write(signature)
    return signature

def rsaSignatureVerify(fileName, variation, publicFileName, signatureFileName):
    message = readForSignature(fileName)
    if signatureFileName == '':
        signatureFileName = fileName.split('.')[0] + '.sig'
    signature = readForSignatureSig(signatureFileName)
    if message and signature:
        hashedMessage = SHA256.new()
        hashedMessage.update(str.encode(message))
        publicKey = RSA.importKey(readPublicKey(variation, publicFileName))
        verifier = PKCS1_PSS.new(publicKey)
        if verifier.verify(hashedMessage, signature):
            print('The signature for '+ str(fileName)+' is valid!\n')
        else:
            print('No, the file was signed with the wrong private key or modified\n')
        return
    else:
        print("File not found in /rsa-signature folder\n")
        return

def readFileForSHA(fileName):
    content = ''
    try:
        with open('sha256/'+fileName, 'r') as readFile:
            content = readFile.read()
    except IOError as e:
        if e.errno != errno.ENOENT:
            raise
    if content:
        return content
    else:
        print("File is not found\n")
        return
    
def generateSHAHashed(content):
    hashed = SHA256.new()
    hashed.update(content)
    return hashed

def drawGraph(timeElapses, typesOfFunction):
    plt.bar(typesOfFunction, timeElapses)
    plt.title("Elapsed Times Graph")
    plt.xlabel("Function types")
    plt.ylabel("Elapsed time")
    plt.xticks(typesOfFunction, rotation=90)
    plt.show()
    
def simulation():
    timeElapses = []
    typesOfFunction = []
    
    gotIt = True
    while(gotIt):
        print("\nPlease choose one option: \n")
        print("1. AES encryption and decryption\n")
        print("2. RSA encryption and decryption\n")
        print("3. RSA Signature\n")
        print("4. SHA-256 hashing\n")
        print("5. EXIT\n")
        
        chosenOne = input("Please type 1 or 2 or 3 or 4 to choose:\n")
        aesGot = True
        rsaGot = True
        rsaSignature = True
        sha256Got = True
        if (chosenOne == "1" and aesGot):
            print("Please choose a mode:\n")
            print("a.ECB\n")
            print("b.CFB\n")
            modeChosen = input("Please type a or b to choose mode\n")
            print("\n")
            print("i. AES-128\n")
            print("ii. AES-192\n")
            print("iii. AES-256\n")
            variationChosen = input("Please type i or ii or iii to choose Key Length\n")
            
            if modeChosen and variationChosen:
                keyChosen = input("Please write a key here (MAX 16 bytes for AES-128, 24 bytes for AES-192, and 32 bytes for AES-256). If longer is given, will be taken first 16/24/32 characters. :\n")
                aesKeyWrite(keyChosen)
                keyFromFile = aesKeyRead()
                if variationChosen == "i":
                    variationChosen = "aes-128"
                elif variationChosen == "ii":
                    variationChosen = "aes-192"
                else:
                    variationChosen = "aes-256"
                
                if modeChosen == "a":
                    modeChosen = "ecb"
                else: 
                    modeChosen = "cfb"
                    
                while(aesGot):
                    typeChosen = input("Want to encrypt or decrypt? Type 'e' to encrypt, 'd' to decrypt : \n")
                    if typeChosen.lower() == 'e':    
                        message = input("Please write a message: \n")
                        timeStart = time()
                        aes(message, keyFromFile, variationChosen, modeChosen, typeChosen)
                        timeEnd = time()
                        elapsedTime = timeEnd - timeStart
                        timeElapses.append(elapsedTime)
                        specialTypeName = "Encryp-"+str(variationChosen)+'-'+str(modeChosen)
                        typesOfFunction.append(specialTypeName)
                        
                    else:
                        fileName = input("Please write your fileName (inside /aes folder)\n")
                        timeStart = time()
                        aes(fileName, keyFromFile, variationChosen, modeChosen, typeChosen)
                        timeEnd = time()
                        elapsedTime = timeEnd - timeStart
                        timeElapses.append(elapsedTime)
                        specialTypeName = "Decryp-"+str(variationChosen)+'-'+str(modeChosen)
                        typesOfFunction.append(specialTypeName)
                    
                    exitText = input("Want to encrypt/decrypt again? Type 'y' to continue, and 'n' to exit \n")
                    
                    if exitText.lower() == 'n':
                        aesGot = False
                        
        elif chosenOne == "2" and rsaGot:
            print("\nPlease choose key length for RSA encryption/decryption:\n")
            print("a. RSA-1024\n")
            print("b. RSA-2048\n")
            print("c. RSA-4096\n")
            itemChosen = input("Please type a or b or c to choose:\n")
            variationChosen = 1024
            if itemChosen == "a":
                privateFileName, publicFileName = keyGenerationAndStore(1024)
                variationChosen = 1024
            elif itemChosen == "b":
                privateFileName, publicFileName = keyGenerationAndStore(2048)
                variationChosen = 2048
            else:
                privateFileName, publicFileName = keyGenerationAndStore(4096)
                variationChosen = 4096
            
            print("Public and Private keys have been created in rsa/ folder :)\n")
    
            while(rsaGot):
                typeChosen = input("Want to encrypt or decrypt? Type 'e' to encrypt, 'd' to decrypt : \n")
                if typeChosen.lower() == 'e':    
                    message = input("Please write a message: \n")
                    timeStart = time()
                    rsa(int(variationChosen), message, typeChosen, publicFileName, privateFileName)
                    timeEnd = time()
                    elapsedTime = timeEnd - timeStart
                    timeElapses.append(elapsedTime)
                    specialTypeName = "Encryp-RSA-"+str(variationChosen)
                    typesOfFunction.append(specialTypeName)
                else:
                    fileName = input("Please write your fileName (inside /rsa folder)\n")
                    timeStart = time()
                    rsa(int(variationChosen), fileName, typeChosen, publicFileName, privateFileName)             
                    timeEnd = time()
                    elapsedTime = timeEnd - timeStart
                    timeElapses.append(elapsedTime)
                    specialTypeName = "Decryp-RSA-"+str(variationChosen)
                    typesOfFunction.append(specialTypeName)
                    
                exitText = input("Want to encrypt/decrypt again? Type 'y' to continue, and 'n' to exit \n")
                
                if exitText.lower() == 'n':
                    rsaGot = False
            
        elif chosenOne == "3" and rsaSignature:
            print("\nPlease choose key length for RSA signature:\n")
            print("a. RSA-1024\n")
            print("b. RSA-2048\n")
            print("c. RSA-4096\n")
            itemChosen = input("Please type a or b or c to choose:\n")
            variationChosen = 1024
            if itemChosen == "a":
                privateFileName, publicFileName = keyGenerationAndStore(1024)
                variationChosen = 1024
            elif itemChosen == "b":
                privateFileName, publicFileName = keyGenerationAndStore(2048)
                variationChosen = 2048
            else:
                privateFileName, publicFileName = keyGenerationAndStore(4096)
                variationChosen = 4096
            
            print("Public and Private keys have been created in rsa/ folder :)\n")
        
            while(rsaSignature):
                typeChosen = input("Want to CreateSignature or Verify for a file? Type 'c' to create, 'v' to verify : \n")
                if typeChosen.lower() == 'c':
                    fileName = input("Please write your fileName to create signature (inside /rsa-signature folder)\n")
                    content = readForSignature(fileName)
                    if content:
                        timeStart = time()
                        message = rsaSignatureCreate(fileName, content, variationChosen, privateFileName)
                        timeEnd = time()
                        elapsedTime = timeEnd - timeStart
                        timeElapses.append(elapsedTime)
                        specialTypeName = "Sig-RSA-create-"+str(variationChosen)
                        typesOfFunction.append(specialTypeName)
                        print("RSA signature of "+"rsa-signature/"+fileName+" is"+str(message)+ " using RSA-"+ str(variationChosen))
                else:
                    fileName = input("Please write your fileName to verify signature (inside /rsa-signature folder)\n")
                    signatureFileName = input("Please write your signature file name to verify signature (inside /rsa-signature folder)\n")
                    timeStart = time()
                    rsaSignatureVerify(fileName, variationChosen, publicFileName, signatureFileName)
                    timeEnd = time()
                    elapsedTime = timeEnd - timeStart
                    timeElapses.append(elapsedTime)
                    specialTypeName = "Sig-RSA-verify-"+str(variationChosen)
                    typesOfFunction.append(specialTypeName)
                    
                exitText = input("Want to create.verify again? Type 'y' to continue, and 'n' to exit \n")
                
                if exitText.lower() == 'n':
                    rsaSignature = False
        
        elif chosenOne == "4" and sha256Got:
            fileName = input("Please write your fileName to generate a SHA-256 hash of your file (file should be inside /sha256 folder)\n")
            content = readFileForSHA(fileName)
            if content:
                hashedContent = generateSHAHashed(str.encode(content))
                print("SHA256 hash for "+str(fileName)+" is:")
                print(hashedContent)
                print('\n')
            else:
                sha256Got = False

        else:
            if len(timeElapses) and len(typesOfFunction):
                print(timeElapses, typesOfFunction)
                drawGraph(timeElapses, typesOfFunction)
            gotIt = False


simulation()
                
                
            
        












