# -*- coding: utf-8 -*-
"""
Created on Sun May 14 08:43:21 2023

@author: Omer Sommerstein, Dima Chudnovsky, Shahar Vachiler, Shachar Dalal
"""

import hashlib
import random

# Elliptic Curve parameters
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F  # prime field
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141  # order of G
a = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141  # coefficient a
b = 0x0000000000000000000000000000000000000000000000000000000000000007  # coefficient b
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)  # base point
h = 1  # cofactor

def mod_inverse(a, m):
    # Calculate the modular inverse of a modulo m using extended Euclidean algorithm
    if a < 0:
        a = m + a
    t, new_t = 0, 1
    r, new_r = m, a
    while new_r != 0:
        quotient = r // new_r
        t, new_t = new_t, t - quotient * new_t
        r, new_r = new_r, r - quotient * new_r
    if r > 1:
        raise ValueError("a is not invertible")
    if t < 0:
        t += m
    return t

def point_addition(p1, p2):
    # Perform point addition of two points on the elliptic curve
    if p1 is None:
        return p2
    if p2 is None:
        return p1

    x1, y1 = p1
    x2, y2 = p2

    if x1 == x2 and y1 != y2:
        return None

    if p1 == p2:
        m = (3 * x1 * x1 + a) * mod_inverse(2 * y1, p) % p
    else:
        m = (y1 - y2) * mod_inverse(x1 - x2, p) % p

    x3 = (m * m - x1 - x2) % p
    y3 = (m * (x1 - x3) - y1) % p

    return x3, y3

def scalar_multiplication(k, p):
    # Perform scalar multiplication of a point on the elliptic curve
    result = None
    current = p
    while k > 0:
        if k & 1 == 1:
            result = point_addition(result, current)
        current = point_addition(current, current)
        k >>= 1
    return result

def generate_key_pair():
    # Generate a new ECDSA key pair
    private_key = random.randint(1, n - 1)
    public_key = scalar_multiplication(private_key, G)
    return private_key, public_key

def sign(private_key, message):
    # Sign a message using the private key
    z = int.from_bytes(hashlib.sha256(message).digest(), 'big')
    k = random.randint(1, n - 1)