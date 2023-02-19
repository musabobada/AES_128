#############################################
###########  HELPERS FUNCTIONS  #############
#############################################
def printArray(A):
# function to print 2D Array 
    for i in range(len(A)):
        for j in range(len(A[0])):
            print(A[i][j],end=" ")
        print()
def sBox(row,column):  
# return s-box value for two-digit hex 
    sBoxArray=[
    (0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5 ,0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76),
    (0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0),
    (0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15),
    (0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75),
    (0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84),
    (0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF),
    (0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8),
    (0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2),
    (0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73),
    (0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB),
    (0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79),
    (0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08),
    (0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A),
    (0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E),
    (0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF),
    (0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16)]
    return sBoxArray[row][column]
def sBoxInverse(row,column):
# return invers sBox value for two-digit hex 
    sBoxInverse=[
    [0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB],
    [0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB],
    [0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E],
    [0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25],
    [0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92],
    [0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84],
    [0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06],
    [0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B],
    [0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73],
    [0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E],
    [0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B],
    [0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4],
    [0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F],
    [0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF],
    [0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61],
    [0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D]]
    return sBoxInverse[row][column]
########## STRING,MAATRIX CONVERTION 
def hexStringToHexStateMatrix(hexString):
# converts a block (16 bytes) of string into form of 4x4 matrix 
# each string character converted to ASCII value then
# converted into form of hex value 
# ? EXAMPLE: "A" character become => "0x41"
    stateMatrix = [["0" for _ in range(4)] for _ in range(4)]
    hex=splitString(hexString,2)
    for i in range(4):
        for j in range(4):
            stateMatrix[j][i] = hex[i*4+j].zfill(2)
    return stateMatrix
def hexStateMatrixToHexString(stateMatrixHex):
# converts state matrix to a string
# ? EXAMPLE: "0x41" character become => "A"
    string = ""
    for i in range(4):
        for j in range(4):
            string+=stateMatrixHex[j][i]
    return string
def hexStateMatrixToIntNumber(stateMatrixHex):
    string = ""
    for i in range(4):
        for j in range(4):
            string+=stateMatrixHex[j][i]
    return int(string,16)
def matrixToWords(arr):
    words=[0,0,0,0]
    for i in range(4):
        word=""
        for j in range(4):
            word+=arr[j][i]
        words[i]=word
    return words
def plainStringToHexStateMatrix(string):
# converts a block (16 bytes) of string into form of 4x4 matrix 
# each string character converted to ASCII value then
# converted into form of hex value 
# ? EXAMPLE: "A" character become => "0x41"
    stateMatrix = [["0" for _ in range(4)] for _ in range(4)]
    for i in range(4):
        for j in range(4):
            stateMatrix[j][i] = hex(ord(string[i*4+j]))[2:].zfill(2)
    return stateMatrix
def stateMatrixToString(stateMatrixHex):
# converts state matrix to a string
# ? EXAMPLE: "0x41" character become => "A"
    string = ""
    for i in range(4):
        for j in range(4):
            string+=chr(int(stateMatrixHex[j][i],16))
    return string
##########  STRING CONVERTION  
def splitInToBlocks(message):
# split message to blocks of 16 bytes (128 bits)
    blocks=[]
    for i in range(0, len(message), 16):
        blocks.append(message[i:i+16])
    if(len(blocks[-1])<=16):
        blocks[-1]=blocks[-1].ljust(16,"#")
    return blocks
def splitString(word,step):
    words=[word[i:i+step] for i in range(0,len(word),step)]
    return words
def hexStringtoPlainText(hexString):
    hexList=splitString(hexString,2)
    plainText=""
    for i in range(len(hexList)):
        plainText+=chr(int(hexList[i],16))
    return plainText
def hexStringToIntNumber(hexString):
    return int(hexString,16)
def plainStringToHexString(string):
    hexString=""
    for i in range(len(string)):
        hexString+=hex(ord(string[i]))[2:].zfill(2)
    return hexString
################   KEY  
def rotWord(word):
    words=""
    for i in range(8):
        words+=word[(i+2)%8]
    return words
def subWord(word):
    words=""
    bytes=splitString(word,2)
    for i in range(4):
        row=int(bytes[i][0],16)
        column=int(bytes[i][1],16)
        # ! zfill bellow
        words+=hex(sBox(row,column))[2:]
    return words
def keyExpansion(key):
    hexKey=""
    for i in range(len(key)):
        hexKey+=hex(ord(key[i]))[2:].zfill(2)
    keyWords=splitString(hexKey,8)
    rc=[0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1B000000, 0x36000000]
    intWords=[0 for i in range(44)]
    for i in range(4):
        intWords[i]=int(keyWords[i],16)
    for i in range(4,44):
        if (i%4==0):
            # ! zfill bellow
            intWords[i]=rc[(i//4)-1]^int(subWord(rotWord(hex(intWords[i-4])[2:].zfill(8))),16)
            continue
        intWords[i]=intWords[i-1]^intWords[i-4]
    keys=[0 for _ in range(11)]
    for i in range(0,44,4):
        # ! zfill bellow
        keys[i//4]=int(hex(intWords[i])[2:].zfill(8)+hex(intWords[i+1])[2:].zfill(8)+hex(intWords[i+2])[2:].zfill(8)+hex(intWords[i+3])[2:].zfill(8),16)
    # return words,keys,len(keys[0])//2
    return keys
def inverseRotWord(word):
    words=""
    for i in range(8):
        words+=word[(i-2)%8]
    return words
def inverseSubWord(word):
    words=""
    bytes=splitString(word,2)
    for i in range(4):
        row=int(bytes[i][0],16)
        column=int(bytes[i][1],16)
        #! zfill bellow
        words+=hex(sBoxInverse(row,column))[2:]
        #  words+=hex(sBoxInverse(row,column))[2:].zfill(8)
    return words
################   MATRIX   
def matrixMult(m1,m2):
    if(len(m2)!=len(m1[0])):
        print("nooo")
        return
    x=range(len(m1))
    y=range(len(m2[0]))
    z=range(len(m2))
    arr=[[0 for _ in y ] for _ in x]
    for i in x:
        for j in y:
            sum=0
            for k in z:
                    sum+=m1[i][k]*m2[k][j]
            arr[i][j]=sum
    return arr
def shiftRows(matrix):
# shift rows of matrix according to AES Standards 
    tempMatrix=[i[:] for i in matrix]
    for i in range(4):
        for j in range(4):
            tempMatrix[i][j]=matrix[i][(j+i)%4].zfill(2)
    return tempMatrix
def matrixSub(matrix):
# return s-box values for state matrix 
    tempMatrix=[i[:] for i in matrix]
    for i in range(4):
        for j in range(4):
            row=int(matrix[i][j][0],16)
            column=int(matrix[i][j][1],16)
            tempMatrix[i][j]=hex(sBox(row ,column))[2:].zfill(2)
    return tempMatrix
def inverseShiftRows(matrix):
# inverse shifted rows to get baack state matrix before shifting 
    tempMatrix=[i[:] for i in matrix]
    for i in range(4):
        for j in range(4):
            tempMatrix[i][j]=matrix[i][(j-i)%4]
    return tempMatrix
def matrixInverseSub(matrix):
# return inverse s-box values for state matrix 
    for i in range(4):
        for j in range(4):
            row=int(matrix[i][j][0],16)
            column=int(matrix[i][j][1],16)
            matrix[i][j]=hex(sBoxInverse(row,column))[2:].zfill(2)
    return matrix

#############################################
###########  MAIN AES FUNCTION  #############
#############################################

########## ? TESTING ###########
key="i love python3.9"
testMessage = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ"
message=testMessage[:16]
mixArray=[
    [0x02,0x03,0x01,0x01],
    [0x01,0x02,0x03,0x01],
    [0x01,0x01,0x02,0x03],
    [0x03,0x01,0x01,0x02]
    ]
########## AES ENCRYPTION
def AES_Encrypt(plainText,key):
    message=plainText
    keys=keyExpansion(key)
    message=plainStringToHexString(message)
    message=hexStringToIntNumber(message)
    message=hex(message^keys[0])[2:].zfill(32)
    for i in range(1,11):
        stateMatrix=hexStringToHexStateMatrix(message)
        stateMatrix=matrixSub(stateMatrix)
        stateMatrix=shiftRows(stateMatrix)
        message=hexStateMatrixToHexString(stateMatrix)
        message=hexStringToIntNumber(message)
        message=hex(message^keys[i])[2:].zfill(32)
    return message
########## AES DECRYPTION
def AES_Decrypt(cipherHexText,key):
    message=cipherHexText
    # print(message)
    keys=keyExpansion(key)
    message=hexStringToIntNumber(message)
    message=hex(message^keys[10])[2:].zfill(32)   
    for i in range(9,-1,-1):
        stateMatrix=hexStringToHexStateMatrix(message)
        stateMatrix=inverseShiftRows(stateMatrix)
        stateMatrix=matrixInverseSub(stateMatrix)
        message=hexStateMatrixToHexString(stateMatrix)
        # print(message)
        message=hexStringToIntNumber(message)
        message=message^keys[i]
        message=hex(message)[2:].zfill(32)
    message=splitString(message,2)
    plainText=""
    for i in message:
        plainText+=chr(int(i,16))
    return plainText

########## INPUT
def main_Enc(message,key):
    if(len(key)!=16):
        print("key lenght is not 16-Bit long")
        exit()
    messages=splitInToBlocks(message)
    cipherText=""
    for i in messages:
        cipherText+=AES_Encrypt(i,key)
    return "cipherText : " +cipherText
def main_Dec(cipherText,key):
    if(len(key)!=16):
        print("key lenght is not 16-Bit long")
        exit()
    cipherTexts=splitString(cipherText,32)
    plainText=""
    for i in cipherTexts:
        plainText+=AES_Decrypt(i,key)
    return "plainText : " +plainText

message=input("Enter message to be encrypted \n>>>")
key=input("Enter key  (16-Bit long)\n>>>")
print(main_Enc(message,key))
cipherText=input("\nEnter message to be decrypted \n>>>")
print(main_Dec(cipherText,key))
# print(AES_Encrypt(message,key))
# print(AES_Decrypt("ca321a6eda7ae1e22026f7e42283e5a9",key))