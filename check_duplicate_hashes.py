def check_duplicate_hashes(log_file):
    """
    Checks for duplicate hash values in the hash log file.

    Args:
        log_file (str): The path to the hash log file.

    Returns:
        list: A list of tuples containing filenames with duplicate hash values.
    """
    hash_dict = {}
    duplicates = []

    # Read hash log file
    with open(log_file, "r") as f:
        lines = f.readlines()

    # Parse each line and check for duplicates
    for line in lines:
        parts = line.strip().split(" ")[4:]
        print(parts)
        dash, hash_value, filename, hash_algorithm = parts
        if hash_value in hash_dict:
            hash_dict[hash_value].append(filename)
        else:
            hash_dict[hash_value] = [filename]

    # Find duplicates
    for hash_value, filenames in hash_dict.items():
        if len(filenames) > 1:
            duplicates.append(tuple(filenames))
    if(duplicates):
        print("Duplicate hash values found:")

        for filenames in duplicates:
                print("Files with the same hash:", filenames)

                #logs the duplicate hash value to master_log.txt
                with open("master_log.txt", "a") as f:
                    f.write(f"hash_duplicate;{filenames}\n")
    else:
        print("No duplicate hash values found.")

    return duplicates

def main():
    log_file = "./logs/hash_log.log"
    duplicates = check_duplicate_hashes(log_file)
    

if __name__ == "__main__":
    main()
