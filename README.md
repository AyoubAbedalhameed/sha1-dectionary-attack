The Solution Theory:

Encryption:
The encryption operation of my solution depends on determining
all of the indexes of plain text characters for each column one by one as the
following:
  → Ciphertext= {Column_1}{Column_2}{..}{Coulmn_K}
  -> Column_i = {PlainText[i], PlainText[i+Shift_F + 1], PlainText[i+Shift_B +
  1], ...}

Such that:
• PlainText = The input plaint text given by the user.
• K = The Key Value.
• Column_Index = Column number starting from 1
• Shift_F: Shift Value in the forward, this value indicates the number
of characters in the plaintext between the current character in specific
column and the next character in the same column in the forward way
(Black in Diagram):
Shift_F = (K – Column_Index)*2 + 1 : Column_Index != K
Shift_F = (2*K – 3)
: Column_Index = K


• Shift_B: Shift Value in the Backword operation (Red in Diagram):
Shift_B = (2*K – 3) : Column_Index = K || Column_Index = 1
Shift_B = (Column_Index -1)*2 : Else# PassCracker
Python script for cracking passwords given in a shadow file, works in multiple modes.


Decryption:
The Decryption operation done by tracing the cipher text characters one bye one, and set each character in the
right index in the plain text as the following:
  • Received CipherText= {Column1}{Column2}{Column3}..{ColumnK}
  • for all value of I in the set {i>=0 && i<len(Ciphertext)}
  Plaintext[Index] = CipherText[i]
  • The Index value foe each round (for each character) can be calculated using find_index Function
  that depends on :-
    1- The current column number.
    2- The the index of character in the column (Odd, Even)
    3- The Key
