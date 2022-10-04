def splitIntoCharacters(word):
    return [i for i in word]

def findCharacters(string):
    allCharacters = []
    punctuations = [",", ".", ";", "!", "?", "-", "'", "(", ")","=","+"]
    for i in string.split():
        for j in splitIntoCharacters(i):
            if j not in punctuations:
                allCharacters.append(j)
    return allCharacters

def procedure(text, baseCharacters, mode, charactersOfKey):
    punctuations = [",", ".", ";", "!", "?", "-", "'", "(", ")","=","+"]
    encryptedSentece = ""
    length = len(text.split())
    count = 0
    characterIteration = 0
    for i in text.split():
        singleWord = ""
        for j in splitIntoCharacters(i):
            if j not in punctuations:
                alphabetIndex = baseCharacters.index(j.lower())
                keyIndex = baseCharacters.index((charactersOfKey[characterIteration]).lower())
                if mode.upper() == 'E' :
                    if j.isupper():
                        singleWord += (baseCharacters[(alphabetIndex+keyIndex) % 26]).upper()
                    else:
                        singleWord += baseCharacters[(alphabetIndex+keyIndex) % 26]
                else:
                    if j.isupper():
                        singleWord += (baseCharacters[(alphabetIndex-keyIndex) % 26]).upper()
                    else:
                        singleWord += baseCharacters[(alphabetIndex-keyIndex) % 26]

                characterIteration += 1
            else:
                singleWord += j
        if count + 1 == length:
            encryptedSentece += singleWord
        else:
            encryptedSentece += singleWord + " "
        count += 1
    return encryptedSentece

def simulation(baseCharacters):
    gotIt = True
    while(gotIt):
        cipherText = input("\nPlease enter your cipher text: \n")
        key = input("\nPlease enter a key with which you want to encrypt or decrypt: \n")
        mode = input("\nWhat do you want? Encryption or Decryption ? For encryption, press single 'e'. Any other character for decryption: \n")

        charactersOfCipher = findCharacters(cipherText)
        keyCharacters = findCharacters(key)
        iterations = int(len(charactersOfCipher)/len(keyCharacters))
        rest = len(charactersOfCipher) - (iterations * len(keyCharacters))
        charactersOfKey = []
        for i in range(iterations):
            for j in keyCharacters:
                charactersOfKey.append(j)
        for r in range(rest):
            charactersOfKey.append(keyCharacters[r])
        result = procedure(cipherText, baseCharacters, mode, charactersOfKey)
        print(result,'\n')
        satified = input("\nDo you want to test another one? For yes, press 'y'. Any character means NO.\n")
        if satified.lower() != "y":
            gotIt = False

alphabets = ['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z']
simulation(alphabets)