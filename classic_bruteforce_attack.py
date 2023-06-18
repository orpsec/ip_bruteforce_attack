import itertools
import string
import hashlib
import logging
import requests

def bruteforce(target_hash, charset, minlength, maxlength, hash_algorithms):
    logger = logging.getLogger('bruteforce')
    logger.setLevel(logging.INFO)

    # Sending a request to get the IP address
    try:
        ip_address = requests.get('https://api.ipify.org').text
        logger.info(f'IP address: {ip_address}')
    except requests.RequestException:
        logger.warning('Failed to retrieve IP address.')

    for length in range(minlength, maxlength + 1):
        for combination in itertools.product(charset, repeat=length):
            attempt = ''.join(combination)
            hashed_attempts = hash_strings(attempt, hash_algorithms)
            for algorithm, hashed_attempt in hashed_attempts.items():
                if hashed_attempt == target_hash:
                    logger.info(f'Password found: {attempt} (Hash algorithm: {algorithm})')
                    return attempt, algorithm
    logger.info('Password not found.')
    return None, None

def hash_strings(string, hash_algorithms):
    hashed_strings = {}
    for algorithm in hash_algorithms:
        hash_object = hashlib.new(algorithm)
        hash_object.update(string.encode('utf-8'))
        hashed_strings[algorithm] = hash_object.hexdigest()
    return hashed_strings

# Define the target hash and character set
target_hash = "5f4dcc3b5aa765d61d8327deb882cf99"  # Example: "password" hash
charset = string.ascii_lowercase + string.ascii_uppercase + string.digits

# Define the minimum and maximum password length
minlength = 1
maxlength = 8

# Define the hash algorithms
hash_algorithms = ["md5", "sha1", "sha256", "sha512", "blake2b"]

# Logging configuration
log_filename = 'bruteforce.log'
logging.basicConfig(filename=log_filename, level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# Perform the brute force attack
result, algorithm = bruteforce(target_hash, charset, minlength, maxlength, hash_algorithms)

# Check the result
if result:
    print(f"Password found: {result} (Hash algorithm: {algorithm})")
else:
    print("Password not found.")