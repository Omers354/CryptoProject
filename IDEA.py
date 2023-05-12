# -*- coding: utf-8 -*-
"""
Created on Fri May 12 15:14:08 2023

@author: Omer Sommerstein, Dima Chudnovsky, Shahar Vachiler, Shachar Dalal
"""

import secrets
import os

#IDEA in CBC mode
class Idea:
    def __init__(self, plaintext):
        #Generating IDEA random key
        self.key = os.random(16)
        #Generating IV 
        self.iv = secrets.token_bytes(16)
        self.plaintext = plaintext
        self.text_blocks = self._generate_blocks()
        
    def encrypt(self):
        ciphertext = b''
        previous_block = self.iv
        # Encrypt each block using CBC mode
        for block in self.text_blocks:
            encrypted_block = self._encrypt_block(block, self.key, previous_block)
            ciphertext += encrypted_block
            previous_block = encrypted_block
        return ciphertext
    
    def _generate_blocks(self):
        # Convert a string text to bytes
        text_bytes = self.plaintext.encode('utf-8')
        # Calculate the number of blocks needed
        num_blocks = len(text_bytes) // 8
        # Split the string text into blocks
        self.text_blocks = [text_bytes[i * 8:(i + 1) * 8] for i in range(num_blocks)]
        # Pad the last block if necessary
        last_block = text_bytes[num_blocks * 8:]
        if len(last_block) < 8:
            padding_length = 8 - len(last_block)
            last_block += b'\x00' * padding_length
        self.text_blocks.append(last_block)
    
    def _xor_bytes(a, b):
        return bytes(x ^ y for x, y in zip(a, b))

    def _encrypt_block(self, block, iv):
        # XOR the block with the IV
        block = self._xor_bytes(block, iv)
        # Perform encryption using the IDEA algorithm and the key
        encrypted_block = self._idea_encrypt(block)
        # Return the new IV for the next block
        return encrypted_block
        
    def _idea_encrypt(self, block):
        # Split the 64-bit block into 16-bit halves
        x1, x2 = int.from_bytes(block[:2], 'big'), int.from_bytes(block[2:], 'big')
        # Generate subkeys from the 128-bit key
        round_keys = self._generate_round_keys()
        # Perform the encryption rounds
        for i in range(8):
            x1, x2 = self._round_function(x1, x2, round_keys[i])
        # Perform the final encryption round
        x1, x2 = self._final_round(x1, x2, round_keys[8])
        # Convert the 16-bit halves back to bytes
        encrypted_block = x1.to_bytes(2, 'big') + x2.to_bytes(2, 'big')
        return encrypted_block
    
    def _generate_round_keys(self):
        round_keys = []
        key_words = [int.from_bytes(self.key[i:i + 2], 'big') for i in range(0, 16, 2)]
        for i in range(9):
            round_keys.append(key_words[i % 8])
            key_words[i % 8] = ((key_words[i % 8] << 9) | (key_words[(i + 1) % 8] >> 7)) & 0xFFFF
        return round_keys
    
    def _multiply(a, b, modulus):
        result = (a * b) % modulus
        if result == 0 and (a != 0 or b != 0):
            result = modulus
        return result

    def _add(a, b, modulus):
        result = (a + b) % modulus
        return result

    def _round_function(self, x1, x2, round_key):
        # Perform the multiplication and modulo operations
        x1 = self._multiply(x1, round_key[0], 0x10001)  # Modulo 2^16 + 1
        x2 = self._add(x2, round_key[1], 0x10000)       # Modulo 2^16
        # Perform the bitwise XOR and addition operations
        x1 ^= x2
        x1 = self._multiply(x1, round_key[2], 0x10001)  # Modulo 2^16 + 1
        x2 = self._add(x1, x2, 0x10000)                 # Modulo 2^16
        # Swap the values of x1 and x2
        x1, x2 = x2, x1
        return x1, x2
    
    def _final_round(self, x1, x2, round_key):
        # Perform the multiplication and modulo operations
        x1 = self._multiply(x1, round_key[0], 0x10001)  # Modulo 2^16 + 1
        x2 = self._add(x2, round_key[1], 0x10000)       # Modulo 2^16
        # Swap the values of x1 and x2
        x1, x2 = x2, x1
        return x1, x2