# -*- coding: utf-8 -*-
"""
Created on Fri May 12 15:31:38 2023

@authors: Omer Sommerstein, Dima Chudnovsky, Shahar Vachiler, Shachar Dalal
"""

import random
import math

class MerkleHellman:
    def __init__(self):
        self.sequence = self._generate_superincreasing_sequence(8)
        self.mod = self._generate_mudolos()
        self.multiplier = self._generate_multiplier()
        self.key = self.generate_public_key()
    
    def _generate_superincreasing_sequence(self, length):
        sequence = [random.randint(1, 10)]
        for _ in range(length - 1):
            sequence.append(sum(sequence) + random.randint(1, 10))
        return sequence
    
    def _generate_mudolos(self):
        return sum(self.sequence) + random.randint(1, 10)
        
    def _generate_multiplier(self):
        while True:
            number = random.randint(2, self.mod - 1)
            if math.gcd(number, self.mod) == 1:
                return number
    
    def generate_public_key(self):
        return [(element * self.multiplier) % self.mod for element in self.sequence]

def main():
    mh = MerkleHellman()
    print(mh.key)
    
main()