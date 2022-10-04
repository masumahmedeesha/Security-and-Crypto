def splitIntoCharacters(word):
    return [i for i in word]

def caeser(string, k, alphabets):
    punctuations = [",", ".", ";", "!", "?", "-", "'", "(", ")","=","[","]","{","}","+"]
    decryptedSentence = ""
    count = 0
    length = len(string.split())
    for i in string.split():
        singleword = ""
        for j in splitIntoCharacters(i):
            if j not in punctuations:
                if j.isupper():
                    singleword += alphabets[(alphabets.index(j.lower()) - k) % 26].upper()
                else:
                    singleword += alphabets[(alphabets.index(j.lower()) - k) % 26]
        if (count + 1) == length:
            decryptedSentence += singleword
        else:
            decryptedSentence += singleword + ' '
        
        count +=1
    return decryptedSentence

def simulation(alphabets):
    gotIt = True
    text = input("\nPaste your ciphertext below to decipher using Caesar cipher:\n")
    while(gotIt):
        value = input("\nInput a key (number) to decipher your ciphertext:\n")
        result = caeser(text, int(value), alphabets)
        print(result,'\n')
        satified = input("\nDo you want to test with another key? For yes, press 'y'. Any character means NO.\n")
        if satified.lower() != "y":
            gotIt = False

alphabets = ['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z']
simulation(alphabets)