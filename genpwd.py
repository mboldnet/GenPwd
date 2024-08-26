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
