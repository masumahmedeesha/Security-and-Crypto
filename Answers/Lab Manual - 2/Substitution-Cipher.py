def splitIntoCharacters(word):
    return [i for i in word]

def findFrequency(string):
    allCharacters = []
    punctuations = [",", ".", ";", "!", "?", "-", "'", "(", ")", "="]
    for i in string.split():
        for j in splitIntoCharacters(i):
            if j not in punctuations:
                allCharacters.append(j)
    uniqueCharacters = {}
    for i in allCharacters:
        if i in uniqueCharacters:
            uniqueCharacters[i] += 1
        else:
            uniqueCharacters[i] = 1
    characterDistribution = {}
    charactersInOrder = []
    for w in sorted(uniqueCharacters, key=uniqueCharacters.get, reverse=True):
        characterDistribution[w] = round(
            ((uniqueCharacters[w] / len(allCharacters)) * 100), 2
        )
        charactersInOrder.append(w)
    return characterDistribution, charactersInOrder

def replaceOneCharacter(old, new, text):
    return text.replace(old, new)

def replaceCharacters(howMany, text, newOrders, universalOrders):
    newReplacedText = text
    for i in range(howMany):
        newReplacedText = replaceOneCharacter(
            newOrders[i], universalOrders[i], newReplacedText
        )
    return newReplacedText

def simulation(encryptedText, universalOrders):
    encryptedText = encryptedText.upper()
    frequency, hereOrders = findFrequency(encryptedText)
    print("\nFrequency of characters: ", frequency, "\n")
    print("\nCharacters Order according to frequency: ", hereOrders, "\n")

    iGotIt = True
    first = True
    avialableHereOrders = hereOrders
    availableUniversalOrders = universalOrders[:len(avialableHereOrders)]

    while iGotIt:
        print('\n')
        print(avialableHereOrders, '\n')
        print(availableUniversalOrders, '\n')

        replaces = input("\nCharacter will be replaced, replaced character\n")
        chars = [i for i in replaces.strip().split()]
        if chars[0].upper() in avialableHereOrders and chars[1].lower() in availableUniversalOrders:
            if first:
                replacedForever = replaceOneCharacter(
                    chars[0].upper(), chars[1].lower(), encryptedText
                )
            else:
                replacedForever = replaceOneCharacter(
                    chars[0].upper(), chars[1].lower(), replacedForever
                )
            print('\n', replacedForever, chars, "\n")
            avialableHereOrders[avialableHereOrders.index(chars[0].upper())] = "-" + chars[0].upper()
            availableUniversalOrders[availableUniversalOrders.index(chars[1].lower())] = "-" + chars[1].lower()

            satified = input("\nAre you satisfied with the answers? If yes, press 'y'. Any character for NO.\n")
            if satified.lower() == "y":
                iGotIt = False
            first = False
        else:
            print("You have already used these ", chars)

universalOrders = [
    "e",
    "t",
    "a",
    "o",
    "n",
    "h",
    "i",
    "s",
    "r",
    "d",
    "l",
    "u",
    "w",
    "m",
    "g",
    "c",
    "f",
    "y",
    "b",
    "p",
    "k",
    "v",
    "j",
    "x",
    "q",
    "z",
]

X = input("\nPlease paste your cipher TEXT here\n")
if X:
    simulation(X, universalOrders)
else:
    print("You haven't paste nothing")

# IT CNJ FGM ETKMNOF CITMITK MIT JWF JIGFT GK YGK MINM SNMMTK CITMITK OM CNJ ZNB GK FOUIM IT CNJ NJINSTZ MG NJQ NDD MIT HDNFTM JTTSTZ MG DOXT RTFTNMI STMND MIT STND GY CIOEI IT INZ PWJM HNKMNQTF INZ RTTF DNRTDTZ DWFEITGF RWM MITKT CTKT SNFB HDNFTMJ CIOEI DOXTZ N JMNFZNKZ MOSTJENDT MINM MGGQ FG NEEGWFM GY MIT HTKINHJ OFEGFXTFOTFM NDMTKFNMOGF GY ZNB NFZ FOUIM. MIT KNMT GY HDNFTMNKB MWKFOFUJ ZOYYTKTZ, NFZ IT ZOZ FGM QFGC MINM GY MKNFMGK