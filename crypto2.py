#! /usr/bin/env python

# Filename: crypto.py
# Author: Kurt Schuster
# Simple program to do crypto encodeing/decoding
# Date: 19-June-2018

from sys import argv
import re
import ciphers as CI


# Support Utility Functions

def dataReader(file):
    '''Function to read in the contents of a file that contains 'mode', 'string to encode', and 'shift'
    'mode' is either '1' or '2' for either number shift or 'a=b' shift
    'string' is the string to encode
    'shift' is the shift definition '''
    dat = []
    with open(file, 'r') as init:
        for i in init:
            temp = re.split(':', i.strip())
            dat.append(temp[1])

    return dat


def binDataWriter(mode, a, shift, file):
    with open(file, 'bw') as output:
        output.write('Mode:' + str(mode) + '\nString:' + a + '\nShift:' + str(shift))


def vig_kword_adjuster(kword, a):
    '''This functions adjusts the length of the keyword so that they are the same length'''
    while len(kword < a):
        kword = kword + kword

    kword = kword[0:len(a)]

    return kword


def replace_shift(b, a, flag=True):
    '''This function applies a simple letter shift to a string.  In this
    function the shift is a string (b) defining what letter is equal to: example 'e=a'.'''
    A = 'abcdefghijklmnopqrstuvwxyz'
    if flag == True:
        print('True')
        shift = re.split('=', b)
        t_i = A.index(shift[0])
        t_f = A.index(shift[1])
        del_t = t_i - t_f
        print(del_t)

        print(shift)

        print(CI.simpleCaesar(del_t, a))
    else:
        print('False')
        shift = re.split('=', b)
        t_i = A.index(shift[0])
        t_f = A.index(shift[1])
        del_t = -1 * (t_i - t_f)
        print(del_t)

        print(shift)

        print(CI.simple_shift(del_t, a))


def recursive_replace(a):
    '''This function allows for the user to select each individualletter replacement'''
    print(a)
    c = a.copy()
    b = 'a=a'
    while b != 'quit':
        b = input("Enter a letter replacement ('a=b') or 'quit': ")
        print(b)


def iterativeCaesar(string):
    for i in range(26):
        print('{}:\t{}'.format(i, CI.simpleCaesar(i, string)))


# ================
# Class Definition
# ================

class cipher:
    def __init__(self, cipher_name):
        self.cipherName = cipher_name
        self.n_shift = 0
        self.r_shift = 'a=a'
        self.kword = None
        self.mesg = None
        self.c_text = None

    def ciph_print(self):
        print('CIPHER: {}'.format(self.cipherName))
        print('\tMessage: {}'.format(self.mesg))
        print('\tNumber Shift: {}'.format(self.n_shift))
        print('\tReplace Shift: {}'.format(self.r_shift))
        print('\tKeyword: {}'.format(self.kword))
        print('\tCipher Text: {}'.format(self.c_text))

    def set_mesg(self, a):
        '''Function to set the cipher mesage'''
        self.mesg = a

    def set_nShift(self, a):
        '''Function to set the number shift'''
        self.n_shift = a

    def set_rShift(self, a):
        '''Function to set the replacement shift'''
        self.r_shift = a

    def set_kword(self, a):
        '''Function to set the keyword'''
        self.kword = a

    def encrypt_Caesar(self):
        '''Function to encrypt message using Caesar Encryption'''
        self.c_text = CI.simpleCaesar(self.n_shift, self.mesg)

    def decrypt_Caesar(self):
        '''Function to decrypt a message using Caesar Encryption'''
        n = -1 * self.n_shift
        self.mesg = CI.simpleCaesar(n, self.c_text)

    def encrypt_Vigenere(self):
        '''Function to encrypt message using Vigenere Encryption'''

        if self.kword != None:
            print("keyword is valid")
            if len(self.kword) == len(self.mesg):
                print('keyword and mesage are the same length, no adjustment needed')
            else:
                print('keyword and mesage are NOT the same length, adjustment needed')
            self.c_text = CI.simpleVigenere(self.kword, self.mesg)
        else:
            print("keyword is not valid, Please set the keyword using the 'set_keyword()' method")

    def decrypt_Vigenere(self):
        self.mesg = CI.simpleVigenereDE(self.c_text, self.kword)


def main():
    print(argv)
    mode, input_str, shift = dataReader(argv[1])
    mode = int(mode)

    print('Entered String: {}'.format(input_str))
    print('Shift: {}'.format(shift))
    ciph1 = cipher('Test')
    ciph1.set_mesg(input_str)
    ciph1.set_kword(shift)
    ciph1.encrypt_Vigenere()

    # input_str = 'ntbbqfclxbfubjgbxrrcvzcbegnagvagryyvtraprnfrperg'

    ciph1.ciph_print()

    ciph1.decrypt_Vigenere()
    ciph1.ciph_print()


if __name__ == '__main__':
    main()
    # replace_shift( 'a=m', 'ntbbqfclxbfubjgbxrrcvzcbegnagvagryyvtraprnfrperg' )
    # dataReader( 'cryptic1' )
    # recursive_replace( 'Kurt' )
    # binDataWriter( 1, 'qaxz', -6, 'file' )
    # CI.simpleVigenere( 'LEMONLEMONLE','ATTACKATDAWN')
    # CI.simpleVigenereDE( 'lxfopvefrnhr', 'LEMONLEMONLE' )
