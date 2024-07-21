import hashlib
import HashTools
import hmac as hmac_lib

use_hmac = True

# Function to create a signature using hashlib or HMAC
def create_signature(secret, data, hash_function="sha256", use_hmac=False):
    if hash_function == "sha1":
        hash_obj = hashlib.sha1
    elif hash_function == "md5":
        hash_obj = hashlib.md5
    elif hash_function == "sha256":
        hash_obj = hashlib.sha256
    elif hash_function == "sha512":
        hash_obj = hashlib.sha512
    else:
        raise ValueError("Invalid hash function")

    if use_hmac:
        signature = hmac_lib.new(secret, data, hash_obj).hexdigest()
    else:
        signature = hash_obj(secret + data).hexdigest()

    return signature

# Verification function using hashlib or HMAC
def verify_signature(secret, data, signature, hash_function="sha256", use_hmac=False):
    computed_sig = create_signature(secret, data, hash_function, use_hmac)
    return computed_sig == signature

# Function to perform an extension attack
def perform_extension_attack(secret_length, original_data, append_data, original_signature, hash_function="sha256"):
    magic = HashTools.new(hash_function)
    new_data, new_sig = magic.extension(
        secret_length=secret_length, 
        original_data=original_data,
        append_data=append_data, 
        signature=original_signature
    )
    return new_data, new_sig

# Setup context
secret = b"ABC9b2"  # Random secret key
print(f"Secret: {secret}")
original_data = b"username=meet&uid=1"
sig = create_signature(secret, original_data, "md5", use_hmac)

# Attempt to perform the extension attack (should fail with HMAC)
# Note: HashTools is not used here as HMAC is resistant to length extension attacks
try:
    append_data = b"&admin=True"
    # perform_extension_attack is not applicable to HMAC
    new_data, new_sig = perform_extension_attack(len(secret), original_data, append_data, sig, "md5")
    new_valid = verify_signature(secret, new_data, new_sig, "md5", use_hmac)
    print(f"New signature: {new_sig},\nNew data signature valid: {new_valid}")
except Exception as e:
    print("Extension attack failed (as expected with HMAC):", e)

# Verify the original signature
original_valid = verify_signature(secret, original_data, sig, "md5", use_hmac)
print(f"Original signature: {sig},\nOriginal data signature valid: {original_valid}")
