"""
   ---------------------------------------------------------------------------------------------
    This program is a test with the Python cryptography package in which we generate 
      derived key from a given string or byte array and return a Fernet class for 
      use with symmetric cryptography.
    ---------------------------------------------------------------------------------------------  
    As a password generator, the derived key can be used as it has strong cryptography.
    ---------------------------------------------------------------------------------------------
    Marcelo Negreiros - October/2023
    Updated in 2024-08-28 -> I made the program more explanatory
    
"""

import base64
import os
import os.path

# ------ Cryptographics functions
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

__syspwd__: bytes = (
    b"3rM%3DSffQmpXcu9AJvmql09x6Wd5zYkpHs"  # Your Default binay Key. You can change it.
)


def getKey(yourkey: str = ""):
    """
    Creates a cryptographic seed from a string or byte array.
    MN - 29/10/2023
    Returns the key (bytes) for use with Fernet
    """

    if len(yourkey) == 0:
        message = __syspwd__
    else:
        message = yourkey.encode()

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=os.urandom(16),
        iterations=480000,
    )

    key = base64.urlsafe_b64encode(kdf.derive(message))

    return key


def main():

    mykey = input(
        "Enter your Key to generate password or \n   <Enter> to use the program key : "
    )

    _key = getKey(mykey)  # generates a derivade key
    f = Fernet(
        _key
    )  # With the derivaded key, return a Fernet Class to Crypt and Decrypt

    _astring: str = ""

    print(
        f"\nDerived Key Generated: {_key.decode('utf-8')}\n  This key can be used as a strong encryption password."
    )
    print(
        "  ... And you can encrypt and decrypt any data using this generated key.\nHere is an example:\n"
    )

    _astring = input("Type a phrase/text to be encrypted: ")

    _stringEnc = f.encrypt(_astring.encode())

    print(
        f"\nEncrypting string '{_astring}'\n  with the key Derived key above: {_stringEnc.decode()}"
    )
    print(
        f"\nDecrypting string '{_stringEnc.decode()}'\n To get back the typed phrase: {f.decrypt(_stringEnc).decode()}\n\nThat's all!"
    )


if __name__ == "__main__":
    main()
