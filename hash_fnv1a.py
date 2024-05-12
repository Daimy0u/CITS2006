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

# Example usage:
data = b"Hello, world!"
hash_value = fnv1a_hash(data)
print("FNV-1a Hash:", hash_value)
