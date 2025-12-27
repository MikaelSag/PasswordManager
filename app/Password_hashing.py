# password_hashing.py
# Author: Heather Stephens
# Purpose: Secure password hashing and verification for the Secure Password Manager project

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# Configure Argon2id parameters
ph = PasswordHasher(
    time_cost=3,        # Number of iterations (security vs performance)
    memory_cost=65536,  # 64 MB memory usage
    parallelism=2       # Number of CPU threads
)

def hash_password(plain_password: str) -> str:
    """
    Hash a plaintext password using Argon2id.
    The output string includes the salt and parameters.
    """
    return ph.hash(plain_password)

def verify_password(stored_hash: str, provided_password: str) -> bool:
    """
    Verify a user's password against the stored Argon2id hash.
    Returns True if valid, False if not.
    """
    try:
        ph.verify(stored_hash, provided_password)
        return True
    except VerifyMismatchError:
        return False
    except Exception as e:
        print(f"Error verifying password: {e}")
        return False

# Optional: quick test
if __name__ == "__main__":
    # Example usage
    pw = "MySecurePassword123!"
    hashed_pw = hash_password(pw)
    print("Hashed password to store in DB:", hashed_pw)

    # Later, verifying
    print("Password correct?", verify_password(hashed_pw, "MySecurePassword123!"))
    print("Password incorrect?", verify_password(hashed_pw, "WrongPassword"))