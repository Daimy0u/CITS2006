from hashing import SHA256, FNV1a

# Example usage:
message = b"Hello, world!"
hashed_message = SHA256.hash(message)
FNV1a_message = FNV1a.hash(message)
print(hashed_message)
print(FNV1a_message)
