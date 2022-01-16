#!/usr/bin/python3

"""
SE431 Software Security
Course Project
Date: Jan 09, 2021
Student Name: Ayoub Abedalhameed
SN: 124052    
"""


import sys, hashlib, string
from itertools import chain, combinations
from typing import Dict


import argparse 


MyArgParser = argparse.ArgumentParser()

#Defining command line arguments
MyArgParser.add_argument('-shadow', action='store', required=True)
MyArgParser.add_argument('-dictionary', type=str,  action='store')
MyArgParser.add_argument('-debug', help="Runnung the script in the duppuging mode, Printing critical values during the time of execution",  action='store_true')
MyArgParser.add_argument('-ml',type=int,  action='store')

PassedArgs = MyArgParser.parse_args()

#Initilaizing Variables Based on cmd arguments and default values.
Debug = PassedArgs.debug
if PassedArgs.dictionary != None:
    Dictionary = True
else:
    Dictionary = False

if PassedArgs.ml != None:
     MaxPassLength = PassedArgs.ml
else:
    MaxPassLength = 4


if Debug: print ("Debug={0} Dictionary={1} MaxxPassLength={2}".format(Debug, Dictionary, MaxPassLength))





#The folllwing boolians can be used for controling -Mod of Operation-
SHA2 = False
Phase2 = True




#Generating ALPHABETIC chars List
CharsList = list(string.ascii_lowercase)

#Appending English Numbers
for i in range (0, 10):
    CharsList.append(str(i))


#Initilizing Phases (1, 2) Variables
CharsLen = len(CharsList)
LevelCrackedCounter = 0


CombinationsList = []
CurrentString = ""
MyDict = {}
counter = 0 

NumOfArgs = len(sys.argv)

MyCounter = 0   #This counter will be used for counting cracked passwords.
Cracked = []


#Reading Shadow, [Dictionary] files into a "set" and a "list" respectively.
try:
    MyHashesFile = open(PassedArgs.shadow)
    MyShadowSet = set(line.strip().lower() for line in MyHashesFile)  # MyShadowSet will be used for performing MATCHING LOOKUPS Thus Hash Set (Type of HASH Dictionary) is used here  
    if(Dictionary):
        MyDictFile = open(PassedArgs.dictionary)                                 
        DictionaryList = [line.strip() for line in MyDictFile]         #DictionaryList will be traced only thus, I used normal python list.

finally:    
    MyHashesFile.close()
    if(Dictionary):
        MyDictFile.close()

ShadowSetSize = len(MyShadowSet)

#Determining if the given shadow file contains Non-SHA1 Digests, if any: assume it is SHA2 Digest.  
for entry in MyShadowSet:
    if( len(entry) > 40 ): SHA2 = True; break ; 


if Debug: print(MyShadowSet, "ShadowList-Length= ", len(MyShadowSet))





# Phase1: Dictionary Attack.
if(Dictionary):
    for password in DictionaryList :        #Tracing the Dictionry list, One entry at a time.
        passcode = password.encode()        #passode is an object thus it must be encoded first (The value only) to be hashed.
        Hash = hashlib.sha1(passcode)       #Finding the SHA1 Digest. 

        if Debug: print(password, Hash.hexdigest())

        if Hash.hexdigest() in MyShadowSet:  #Checking the existence of digest in the shadow Set, O(log(N)) (Hash Set) 
            
            Cracked.append( "{0:<4}{1:<13}{2:<10}".format(MyCounter+1, password, Hash.hexdigest())   ) #If the digest is found in the set then append it to the Cracked list.

            MyCounter = MyCounter + 1         
            MyShadowSet.remove(Hash.hexdigest())
            if len(MyShadowSet) == 0: print("All Passwords have been cracked in dictionary Phase, Exiting.."); Phase2 = False; break
            if Debug: print("One Password Found!" + ": Pass Index= " + str(MyCounter-1), "New Shadow Length=" + str(len(MyShadowSet)))
            
        else:
            continue




#Phase 2: Bruteforce Attack

#Phase 2.0: Trying Single-Digit Passwords.
if Phase2:
    for c in CharsList:
        
        passcode = c.encode()                   #Encoding 
        Hash = hashlib.sha1(passcode)
        if Debug: print(c, Hash.hexdigest())
        if Hash.hexdigest() in MyShadowSet:
            Cracked.append ("{0:<4}{1:<13}{2:<10}".format(MyCounter+1, c, Hash.hexdigest()))
            MyCounter+= 1
            LevelCrackedCounter += 1
            MyShadowSet.remove(Hash.hexdigest())
            if len(MyShadowSet) == 0: print("BruteForce Phase Ended.\n"); Phase2=False; break
        else:
            continue


#Phase 2.1: Generating ALPANUMERIC Characters Combinations from SCRATCH, I used Lexicographical algorithm that 
#depends on a pointer for each Lexicographical Level, The whole Combinations Sample Space will be traversed by Jumping through All Lexicographical Nodes. 



#Expected Combinations Count can be calculated by the following formula:
    """ ECC = (CharsListLen)^MaxSize + (CharsListLen)^(MaxSize-1) + (CharsListLen)^(MaxSize-2) +  ..  + (CharsListLen)
          
             --> CharsListLen = CharsLen (Discussed Ubove) 
             --> MaxSize = The Maximum Length of the password as a string (In in the Assignment equals 4) 
    
    """
if Phase2:
    for i in range(MaxPassLength, 1, -1):             #Generating ALPHANUMERIC Combinations of different Lengths, starting from MaxLength.
        if Debug: print("Start Brutforcing Passwords of length " + str(i) )
        size = i
        currentpointer = size
        Flag = True

        
        
        
        #Intilizing The Pointers Dictionary, This dictionary will be used as DYNAMIC LIST of Pointers (One Pointer for each Lexicographical Level), Pointer Index will be used as a KEY
        for i in range(1, size+1):
            MyDict[i] = 0                   #All Poiters will be initilaized to zero Thus the algorithm starts from 0.0.0.0 to X.X.X.X such as X = MaxPassLength


        while Flag:
            for i in range(1, size+1):
                CurrentString = CurrentString + CharsList[MyDict[i]]
            
            
            
            passcode = CurrentString.encode()
            Hash = hashlib.sha1(passcode)
            if Hash.hexdigest() in MyShadowSet:            
                Cracked.append( "{0:<4}{1:<13}{2:<10}".format(MyCounter+1, CurrentString, Hash.hexdigest() ))         
                MyShadowSet.remove(Hash.hexdigest())
                MyCounter+=1
                LevelCrackedCounter += 1
                if len(MyShadowSet) == 0: print("Phase 2 Ended.\n"); break


            if Debug: CombinationsList.append(CurrentString);  counter+=1
            CurrentString = ""
            MyDict[currentpointer] += 1                         #Jumping to the Next Lexicographical Node IN THE SAME LEVEL by Increament-then-Test Operation  
            if MyDict[currentpointer] == CharsLen:              #Jumping through Lexicographical Levels.  
                while(True):
                    
                    MyDict[currentpointer] = 0                                                      
                    currentpointer -=1
                    MyDict[currentpointer]+=1
                    if MyDict[currentpointer] < CharsLen:
                        currentpointer = size
                        break
                    elif currentpointer == 1:
                        Flag = False
                        break
        if Debug: print("Level:" + str(i) +  ' '+  str(LevelCrackedCounter) + " Passwords have been cracked")
            
                



if Debug: print("\nCobinations List:\n",  CombinationsList, '\nNumber of Combinatoins= ', counter , '\n')

for entry in Cracked:
    print (entry)
								

print("\n\nConclusion:-\n")
print("     -Number of Cracked Passwords = {}".format(str(MyCounter)))
print("     -Success Rate: {}%".format(  str((MyCounter)/(ShadowSetSize)* 100)   ) )
if Dictionary: print("     -Cracked Using Dictionary: {0}".format(str(MyCounter-LevelCrackedCounter) ) )
print("     -Bruteforced: {0}".format(str(LevelCrackedCounter) ) )

print("\nRemained Hashes: ", len(MyShadowSet))
for entry in MyShadowSet:
    print (entry)                                             
