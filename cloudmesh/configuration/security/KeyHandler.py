import os
import sys
import getpass
from cloudmesh.common.Shell import Shell
from cloudmesh.common.console import Console
from cloudmesh.common.util import path_expand, readfile, writefd, yn_choice
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

class KeyHandler:
    """ 
    Responsible for the loading and creation of keys
    """

    def __init__(self, debug=False, priv=None, pub=None, pem=None):
        # CMS debug parameter
        self.debug = debug
        # pyca Key Objects
        self.priv = priv
        self.pub = pub
        self.pem = pem

    def new_rsa_key(self, byte_size=2048):
        """
        Generates a new RSA private key 
        @param: int: size of key in bytes
        @param: bol: indicates if app must prompt for password
        return: serialized bytes of private the RSA key
        """
        self.priv = rsa.generate_private_key(
            public_exponent=65537,  # do NOT change this!!!
            key_size=byte_size,
            backend=default_backend()
        )

        return self.priv

    def get_pub_key(self, priv=None):
        """
        Given a Pyca private key instance return a Pyca public key instance
        @param priv: the PYCA private key
        return: the pyca RsaPublicKey
        """
        if priv is None:
            Console.error("No key was given")
            sys.exit()
        elif isinstance(priv, rsa.RSAPrivateKey):
            return priv.public_key()
        else:
            raise UnsupportedAlgorithm

    def serialize_key(self, debug=False, key=None, key_type="PRIV",
                      encoding="PEM", format="PKCS8", ask_pass=True):
        """
        @param: debug:      cloudmesh debug flag
        @param: key:        pyca key object
        @param: key_type:   the type of key file [PRIV, PUB]
        @param: encoding:   the type of encoding [PEM, SSH]
        @param: format:     private [PKCS8, OpenSSL], Public [SubjectInfo, SSH]
        @param: ask_pass:   Indicates if the key should have a password
                            (True,False)
        return:             serialized key bytes of the key
        """
        # TODO: add try-catching
        # Ensure the key is initialized
        if key is None:
            if key_type == "PRIV":
                if self.priv is None:
                    Console.error("No key given")
                    sys.exit()
                else:
                    key = self.priv
            elif key_type == "PUB":
                if self.pub is None:
                    Console.error("No key given")
                    sys.exit()
                else:
                    key = self.pub
            else:
                Console.error("No key given")
                sys.exit()

        # Discern formating based on if key is public or private
        key_format = None
        if key_type == "PRIV":
            key_format = serialization.PrivateFormat
        elif key_type == "PUB":
            key_format = serialization.PublicFormat
        else:
            Console.error("key needs to be PRIV or PUB")
            sys.exit()

        # Discern formatting of key
        if key_type == "PRIV":
            if format == "PKCS8":
                key_format = key_format.PKCS8
            elif format == "OpenSSL":
                key_format = key_format.TraditionalOpenSSL
            else:
                Console.error("Unsupported private key format")
                sys.exit()
        elif key_type == "PUB":
            if format == "SubjectInfo":
                key_format = key_format.SubjectPublicKeyInfo
            elif format == "SSH":
                key_format = key_format.OpenSSH
            else:
                Console.error("Unsupported public key format")
                sys.exit()

        # Discern encoding
        encode = None
        if encoding == "PEM":
            encode = serialization.Encoding.PEM
        elif encoding == "SSH":
            encode = serialization.Encoding.OpenSSH
        else:
            Console.error("Unsupported key encoding")
            sys.exit()

        # Discern encryption algorithm (Private keys only)
        # This also assigns the password if given
        enc_alg = None
        if key_type == "PRIV":
            if not ask_pass:
                m = "Key being created without password. "\
                    "This is not recommended."
                Console.warning(m)
                enc_alg = serialization.NoEncryption()
            else:
                pwd = self.requestPass("Password for the new key:")
                if pwd == "":
                    enc_alg = serialization.NoEncryption()
                else:
                    pwd = str.encode(pwd)
                    enc_alg = serialization.BestAvailableEncryption(pwd)

        # Serialize key
        sk = None
        if key_type == "PUB":
            sk = key.public_bytes(encoding=encode, format=key_format)
        elif key_type == "PRIV":
            sk = key.private_bytes(encoding=encode, format=key_format,
                                   encryption_algorithm=enc_alg)
        return sk

    def write_key(self, key = None, path = None, mode = "wb", force = False):
        """
        Writes the key to the path, creating directories as needed"
        @param key:     The data being written yca key instance
        @param path:    Full path including file name
        @param mode:    The mode for writing to the file
        @param force:   Automatically overwrite file if it exists
        """

        # Check if the key is empty
        if key is None:
            Console.error("Key is empty")
            sys.exit()

        if path is None:
            Console.error("Path is empty")
            sys.exit()

        # Create directories as needed for the key
        dirs = os.path.dirname(path)
        if not os.path.exists(dirs):
            Shell.mkdir(dirs)

        if not force:
            # Check if file exists at locations
            if os.path.exists(path):
                Console.info(f"{path} already exists")
                ovwr_r = yn_choice(message=f"overwrite {path}?", default="N")
                if not ovwr_r:
                    Console.info(f"Not overwriting {path}. Quitting")
                    sys.exit()

        # Write the file
        writefd(filename=path, content=key, mode=mode)

    def load_key(self, path="", key_type="PUB", encoding="SSH", ask_pass=True):
        """
        Loads a public or private key from the path using pyca
        @param: str: path to file being loaded
        @param: str: indicates if key is public (PUB) or private (PRIV)
        @param: str: indicates encoding of file (SSH, PEM)
        @param: bol: Flag to ask for the key's password 
        return: rsa.RSAPublicKey, rsa.RSAPrivate, or None
        """
        # Discern target key instance
        key_instance = None
        if key_type == "PUB":
            key_instance = rsa.RSAPublicKey
        elif key_type == "PRIV":
            key_instance = rsa.RSAPrivateKey
        else:
            Console.error("Unsupported key type")
            sys.exit()

        # Discern function from encoding and key type
        load_function = None
        if encoding == "SSH" and key_type == "PUB":
            load_function = serialization.load_ssh_public_key
        elif encoding == "PEM":
            if key_type == "PRIV":
                load_function = serialization.load_pem_private_key
            elif key_type == "PUB":
                load_function = serialization.load_pem_public_key
            else:
                Console.error("Unsupported key type for PEM keys")
                sys.exit()
        else:
            m = f"Unsupported key-type,encoding pair({key_type},{encoding})"
            Console.error(m)
            sys.exit()

        # Discern password
        password = None
        if not ask_pass:
            password = None
        else:  # All other cases should request password
            prompt = f"Password for {path} [press enter if none]: "
            password = self.requestPass(prompt, confirm = False)
            if password == "":
                password = None
            else:
                password = password.encode()

        # Read key file bytes
        data = readfile(path, mode='rb')

        # Attempt to load the formatted contents
        try:
            key = None
            if key_type == "PUB":
                key = load_function(data, default_backend())
            elif key_type == "PRIV":
                key = load_function(data, password, default_backend())

            # Check if key instance is correct
            if isinstance(key, key_instance):
                return key
            else:
                Console.error(f"Key instance must be {key_instance}")
                sys.exit()

        except ValueError as e:
            Console.error(f"Could not properly decode {encoding} key")
            raise e
        except TypeError as e:
            Console.error("""Password mismatch either: 
            1. given a password when file is not encrypted 
            2. Not given a password when file is encrypted""")
            raise e
        except UnsupportedAlgorithm as e:
            Console.error("Unsupported format for pyca serialization")
            sys.exit()
        except Exception as e:
            Console.error(f"{e}")
            sys.exit()

    def reformat_key(self, path = None, key_type = None, use_pem = True,
                    new_format = None, ask_pass = True):

        # Determine filepath
        fp = None
        if path is None:
            kp = path_expand("~/.ssh/id_rsa")
            fp = kp + ".pub"
        else:
            fp = path_expand(path)

        # Discern if we ask for password key type
        if key_type == "PUB":
            ask_pass = False

        # Discern target encoding
        oenc = None # original encoding
        nenc = None # new encoding
        # If converting the key to SSH encoding
        if use_pem:
            if key_type == "PUB":
                oenc = "SSH"
                nenc = "PEM"
            else:
                oenc = nenc = "PEM"
        else: #OpenSSH encoding
            # If user attempts to reformat private key to SSH
            if key_type == "PRIV":
                Console.error("Private keys cannot have SSH encoding")
                sys.exit()
            # Assign original and new encodings
            oenc = "PEM"
            nenc = "SSH"

        # Discern Format
        forma = None
        if key_type == "PUB":
            # If the user did not provide a format decide one
            if new_format is None:
                if use_pem:
                    forma = "SubjectInfo"
                else:
                    forma = "SSH"
            else: # format argument not provided
                forma = new_format
                if forma != "SSH" and forma != "SubjectInfo":
                    m = f"Public keys must have SSH or SubjectInfo format"
                    Console.error(m)
                    sys.exit()
        else: # Private key
            if new_format is None:
                forma = "PKCS8"
            else:
                forma = new_format
                if forma != "PKCS8" and forma != "OpenSSL":
                    m = "Private keys must have PKCS8 or OpenSSL format"
                    Console.error(m)
                    sys.exit()

        # load {key_type} key at {path} with {old_encoding}
        k = self.load_key(path = fp, key_type = key_type,
                          encoding=oenc, ask_pass = ask_pass)

        # searialze key with {new_format} and {new_encoding}
        k = self.serialize_key(key = k,
                                key_type = key_type,
                                encoding = nenc,
                                format = forma,
                                ask_pass = ask_pass)

        # write the key to {path}
        self.write_key(key = k, path = fp, mode = "wb", force = True)

    # noinspection PyPep8Naming
    def requestPass(self, prompt="Password for key:", confirm = True):
        try:
            pwd1 = getpass.getpass(prompt)

            # Request password input twice to confirm input
            if confirm:
                pwd2 = getpass.getpass("Confirm password:")
                if pwd1 == pwd2:
                    return pwd1
                else:
                    Console.error("Mismatched passwords")
                    sys.exit()
            else:
                return pwd1

        except getpass.GetPassWarning:
            Console.error("Danger: password may be echoed")
            sys.exit()
        except Exception as e:
            raise e
