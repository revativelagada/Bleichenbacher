#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Jun 15 09:06:39 2020

@author: revati
"""

import math
import random
import gmpy2

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    g, y, x = egcd(b%a, a)
    return (g, x - (b//a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('No modular inverse')
    return x % m

def generate_prime(bit_length):
        while True:
            lb = 2 ** (bit_length - 1)
            ub = (2 ** bit_length) - 1
            candidate = random.randint(lb, ub)
            if gmpy2.is_prime(candidate):
                return candidate
            

def bytes_to_integer(bytes_obj): #built-in
    return int.from_bytes(bytes_obj, byteorder='big')

def integer_to_bytes(integer):
    k = integer.bit_length()

    # adjust number of bytes
    bytes_length = k // 8 + (k % 8 > 0)

    bytes_obj = integer.to_bytes(bytes_length, byteorder='big')

    return bytes_obj

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


def multiplicative_inverse(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('No inverse')
    return x % m

def is_prime(num):
    if num == 2:
        return True
    if num < 2 or num % 2 == 0:
        return False
    for n in range(3, int(math.sqrt(num))+2, 2):
        if num % n == 0:
            return False
    return True

def generate_key(modulus_length):
    prime_length = modulus_length // 2
   
    '''
    p = int(input("Enter a prime number: "))
    q = int(input("Enter another prime number: "))
    
    if not (is_prime(p) and is_prime(q)):
        raise ValueError('Both numbers must be prime.')
    elif p == q:
        raise ValueError('p and q cannot be equal')
   #p = utils.generate_prime(prime_length)

   #q = utils.generate_prime(prime_length)
    n = p * q
    phi = (p-1) * (q-1)

    #Choose an integer e such that e and phi(n) are coprime
    e = random.randrange(1, phi)

    #Use Euclid's Algorithm to verify that e and phi(n) are coprime
    g = gcd(e, phi)
    while g != 1:
        e = random.randrange(1, phi)
        g = gcd(e, phi)

    #Use Extended Euclid's Algorithm to generate the private key
    d = multiplicative_inverse(e, phi)
    '''
    
    p = generate_prime(prime_length)

    q = p
    while q == p:
        q = generate_prime(prime_length)

    n = p * q
    phi = (p - 1) * (q - 1)
    e = random.randrange(1, phi)

    g = gcd(e, phi)
    while g != 1:
        e = random.randrange(1, phi)
        g = gcd(e, phi)

    d = modinv(e, phi)
    
    public_key = (n, e)
    secret_key = (n, d)

    return public_key, secret_key

def encrypt_integer(public_key, m):
    (n, e) = public_key

    if m > n:
       # print(m)
       # print(n)
        raise Exception("Message is too big for current RSA scheme!")

    return pow(m, e, n)

def decrypt_integer(secret_key, c):
    (n, d) = secret_key

    return pow(c, d, n)

def encrypt_string(public_key, message):
    integer = bytes_to_integer(message) #encoded msg
   #print(integer)
    enc_integer = encrypt_integer(public_key, integer)
    enc_string = integer_to_bytes(enc_integer)

    return enc_string

def decrypt_string(secret_key, ciphertext):
    enc_integer = bytes_to_integer(ciphertext)
    integer = decrypt_integer(secret_key, enc_integer)
    message = integer_to_bytes(integer)

    return message