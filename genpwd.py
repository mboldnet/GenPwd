import base64
import os
import os.path
import sys
import datetime
import random
import hashlib
import platform

# ------ Cryptographics functions
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hmac import HMAC

__syspwd__: str = "3rM%3DSffQmpXcu9AJvmql09x6Wd5zYkpHs"  # Your Default System Key


def getKey(login_password=""):
    """
    create the cryptographic seed object for all system or to a user with a login and password
    MB - 29/12/2023
    Returns the key (bytes) for use with Fernet
    """

    if len(login_password) == 0:
        message = __syspwd__.encode(encoding="utf-8")
    else:
        message = login_password.encode(encoding="utf-8")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=os.urandom(16),
        iterations=480000,
    )

    key = base64.urlsafe_b64encode(kdf.derive(message))

    return key


def main():

    _exit: bool = False
    while not _exit:

        user_name = input("Give me your best email: ")
        user_pwd = input("Now, put a good (secure) password: ")

        if len(user_name) != 0 and len(user_pwd) != 0:
            if (
                input(f"    {user_name},    {user_pwd}       Confirm (y/n)? ").upper()
                == "Y"
            ):
                _exit = True

    print(
        f"Generating the key derivated from your login:\n  [{user_name} and {user_pwd}]:"
    )

    _key = getKey(user_name + user_pwd)
    f = Fernet(_key)

    _astring: str = "The House is green"

    print(f"\nKey Generated: {_key.decode('utf-8')}")

    _stringEnc = f.encrypt(_astring.encode())

    print(f"Encrypting string {_astring} with the key above: {_stringEnc.decode()}")
    print(
        f"Decrypting string {_stringEnc.decode()} to get the phrase: {f.decrypt(_stringEnc).decode()}"
    )


if __name__ == "__main__":
    main()
