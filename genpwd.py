import base64
import os
import os.path

# ------ Cryptographics functions
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

__syspwd__: bytes = b"3rM%3DSffQmpXcu9AJvmql09x6Wd5zYkpHs"  # Your Default System Key


def getKey(yourkey=""):
    """
    create the cryptographic seed object for all system or to a user with a login and password
    MN - 29/12/2023
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

    _key = getKey(mykey)
    f = Fernet(_key)

    _astring: str = ""

    print(f"\nKey Generated: {_key.decode('utf-8')}")
    print(
        "You can encrypt and decrypt any data using this generated key.\nHere is an example:"
    )

    _astring = input("Type a phrase: ")

    _stringEnc = f.encrypt(_astring.encode())

    print(f"\nEncrypting string {_astring} with the key above: {_stringEnc.decode()}")
    print(
        f"Decrypting string {_stringEnc.decode()} to get the phrase: {f.decrypt(_stringEnc).decode()}"
    )


if __name__ == "__main__":
    main()
