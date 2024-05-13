import sys
import os
import random
from datetime import datetime

def fnv1a_hash(data):
    """
    FNV-1a hash function implementation.
    """
    # FNV parameters for 32-bit hash
    FNV_OFFSET_BASIS_32 = 0x811c9dc5
    FNV_PRIME_32 = 0x01000193
    
    # Initialize hash to FNV offset basis
    hash_value = FNV_OFFSET_BASIS_32
    
    # Hash each byte in the data
    for byte in data:
        hash_value ^= byte
        hash_value *= FNV_PRIME_32
        hash_value &= 0xFFFFFFFF  # Limit to 32 bits
    
    # Convert hash value to 50-character hexadecimal string
    hash_str = format(hash_value, '08X')
    hash_str = hash_str.zfill(50)
    
    return hash_str

def main():
    if len(sys.argv) != 2:
        print("Usage: python hash_fnv1a.py <filename>")
        return

    filename = sys.argv[1]

    try:
        with open(filename, 'rb') as file:
            content = file.read()
            hashed_content = fnv1a_hash(content)
            print(hashed_content)

            #send log to hash_log.txt
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open("hash_log.txt", "a") as f:
                f.write(f"{timestamp};{filename};{hashed_content};fnv1a\n")
            

    except FileNotFoundError:
        print(f"File '{filename}' not found.")

if __name__ == "__main__":
    main()
