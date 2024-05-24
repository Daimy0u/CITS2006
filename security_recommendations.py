def generate_recommendations(log_file, recommendation_file):
    """
    Generates recommendations based on the content of the log file.

    Args:
        log_file (str): The path to the log file.
        recommendation_file (str): The path to the recommendation file.
    """
    # Read the log file
    with open(log_file, "r") as f:
        lines = f.readlines()
    recommendation = ""

    # Process each line in the log file
    for line in lines:
        if line.startswith("yara"):
            parts = line.strip().split(";")
            yara_rule = parts[1]
            filename = parts[2]
            recommendation = f"YARA: {filename} is {yara_rule}. Please check this file"

        elif line.startswith("cipher_encryption"):
            parts = line.strip().split(";")
            cipher_encryption = parts[1]
            if cipher_encryption not in ["DH", "ECDH", "ECDSA", "RSA"]:
                recommendation = f"ENCRYPTION: '{cipher_encryption}' is not the standard. Please change."

        
        elif line.startswith("hash_algorithm"):
            parts = line.strip().split(";")
            hash_algorithm = parts[1]
            if hash_algorithm != "sha256":
                recommendation = f"HASH ALGORITHM: '{hash_algorithm}' is not the standard. Please change."

        elif line.startswith("hash_duplicate"):
            parts = line.strip().split(";")
            filenames = eval(parts[1])
            recommendation = f"HASH DUPLICATE: found for files: {filenames}. Please check these files."

        elif line.startswith("hash_outside_business_hours"):
            parts = line.strip().split(";")
            timestamp = parts[1]
            filename = parts[2]
            recommendation = f"HASH OUTSIDE BUSINESS HOURS: '{filename}' was modified outside of business hours (timestamp: {timestamp}). Please investigate."

        else:
            # Skip lines that do not start with "hash_duplicate" or "hash_outside_business_hours"
            continue

        # Append recommendation to recommendation file
        with open(recommendation_file, "a") as rf:
            rf.write(recommendation + "\n")

def main():
    log_file = "master_log.txt"
    recommendation_file = "security_recommendations.txt"
    generate_recommendations(log_file, recommendation_file)
    print("Recommendations generated and written to 'security_recommendations.txt'.")

if __name__ == "__main__":
    main()
