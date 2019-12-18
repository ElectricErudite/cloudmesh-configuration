import os
import sys
from cloudmesh.common.Shell import Shell
from cloudmesh.common.console import Console
from cloudmesh.common.util import path_expand, readfile, writefd
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cloudmesh.configuration.security.KeyHandler import KeyHandler


class CmsEncryptor:
    """ 
    Encrypts bytes for CMS
    I) key generation is outside scope of CmsEncryptor
      1) Generating 2048 bit RSA Private and Public PEM files
        A) Debian
            a) Ensure openssl is installed
            b) Execute: openssl genrsa -aes256 -out <priv_key_name>
            c) Execute:
               openssl rsa -in <priv_name> -outform PEM -pubout -out <pub_name>

      2) Generating 2048 bit RSA Private and Public SSH keys
        A) Debian
            a) ensure ssh-keygen is installed
            b) Execute: ssh-keygen -t rsa -m pem -f <base_priv_and_pub_name>

      2) Generating 384 bit ECC key
        A) Debian 
            a) TODO
    """

    def __init__(self, debug=False):
        self.debug = debug
        self.tmp = path_expand("~/.cloudmesh/tmp")

    # noinspection PyPep8Naming
    def getRandomBytes(self, len_bytes=32):
        rand_bytes = os.urandom(len_bytes)
        return rand_bytes

    # noinspection PyPep8Naming
    def getRandomInt(self, len_bytes=32, order="big"):
        rb = self.getRandomBytes(len_bytes)
        rand_int = int.from_bytes(rb, byteorder=order)
        return rand_int

    def encrypt_rsa(self, pub=None, pt=None, padding_scheme="OAEP"):
        if pub is None:
            Console.error("empty key argument")
            sys.exit()

        if pt is None:
            Console.error("attempted to encrypt empty data")
            sys.exit()

        elif not type(pt) == bytes:
            pt = pt.encode()

        pad = None
        if padding_scheme == "OAEP":
            pad = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                               algorithm=hashes.SHA256(),
                               label=None)
        else:
            Console.error("Unsupported padding scheme")
            sys.exit()

        return pub.encrypt(pt, pad)

    def decrypt_rsa(self, priv=None, ct=None, padding_scheme="OAEP"):
        if priv is None:
            Console.error("empty key arugment")
            sys.exit()
        if ct is None:
            Console.error("attempted to decrypt empty data")
            sys.exit()
        pad = None
        if padding_scheme == "OAEP":
            pad = padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None)
        else:
            Console.error("Unsupported padding scheme")
            sys.exit()

        # return priv.decrypt( ct, pad ).decode()
        return priv.decrypt(ct, pad)

    def decrypt_aesgcm(self, key=None, nonce=None, aad=None, ct=None):
        aesgcm = AESGCM(key)
        pt = aesgcm.decrypt(nonce, ct, aad)
        return pt

    def encrypt_aesgcm(self, data=None, aad=None):
        """
        @param: bytes: the plaintext data 
        @param: bytes: the additional authenticated data (can be public)
        @return: 
            - bytes: AESGCM key object
            - bytes: nonce (random data)
            - bytes: ciphertext
        """
        if data is None:
            Console.error("Attempted to encrypt empty data")
            sys.exit()

        # ALWAYS generate a new nonce. 
        # ALL security is lost if same nonce and key are used with diff text 
        nonce = self.getRandomBytes(12)
        key = AESGCM.generate_key(bit_length=256)
        aesgcm = AESGCM(key)
        ct = aesgcm.encrypt(nonce, data, aad)

        return key, nonce, ct

    def encrypt_file(self, infile=None, outfile=None, enc_aes_key=True,
                     inkey=None):
        """
        Encrypts the file located at filepath using AES-GCM, and encrypt the
        AES key with RSA if indicated. It is the responsibility of the caller 
        to handle the returned key and nonce. 

        @param infile:      Full path to the file that will be encrypted
        @param outfile:     Full path to the desired output location
        @param enc_aes_key: Indicate if AES key should be encrypted with pubkey
        @param inkey:       Full path to the PEM encoded public key 
        @return:
            - bytes: AES-GCM key
            - bytes: nonce (one time random data)
        """

        # Check if filepath exists
        if not os.path.exists(infile):
            Console.error(f"{infile} does not exists")
            sys.exit()

        # Check if the key exists
        if enc_aes_key and not os.path.exists(inkey):
            Console.error(f"{inkey} does not exists")
            sys.exit()

        # Check if filepath is directory
        if os.path.isdir(infile):
            Console.error(f"{infile} is a directory")
            sys.exit()

        # Assign the outfile name if needed
        if outfile is None:
            outfile = os.path.basename(infile) + ".enc"

        # Read the file contents
        contents = readfile(infile)
        contents = contents.encode()

        # Encrypt the file using Symmetric AES-GCM encryption
        k, n, ct = self.encrypt_aesgcm(data=contents, aad=None)

        # Encrypt the key if desired
        if enc_aes_key:
            kh = KeyHandler()
            u = kh.load_key(path=inkey, key_type="PUB",
                            encoding="PEM", ask_pass=False)
            k = self.encrypt_rsa(pub=u, pt=k)

        # Encode the data as integers
        cipher = int.from_bytes(ct, 'big')

        # Write outfile and remove infile
        writefd(filename=outfile, content=str(cipher))
        Shell.rm(infile)

        return k, n

    def decrypt_file(self, infile=None, aes_key=None, nonce=None,
                     outfile=None, dec_aes_key=True, inkey=None, has_pass=True):
        """
        Decrypts the file located at the infile with AES-GCM using the passed
        in bytes of the key and nonce that was generated during encryption. 
        The AES key will be decrypted using RSA if indicated. 
        Note: This is untested with large data files

        @param infile:      Full path to the file that will be decrypted
        @param aes_key:     Bytes of the AES key generated at encryption
        @param nonce:       Bytes of the nonce generated at encryption
        @param outfile:     Full path to the desired output location
        @param dec_aes_key: Indicate if AES key should be decrypted with pubkey
        @param inkey:       Full path to the PEM encoded public key 
        @param has_pass:    Indicates if the private key is password protected
        """
        # TODO: Test with large data files (10GB+)

        # Check if filepath exists
        if not os.path.exists(infile):
            Console.error(f"{infile} does not exists")
            sys.exit()

        # Check if the key exists
        if dec_aes_key and not os.path.exists(inkey):
            Console.error(f"{inkey} does not exists")
            sys.exit()

        # Check if filepath is directory
        if os.path.isdir(infile):
            Console.error(f"{infile} is a directory")
            sys.exit()

        # Assign the outfile name if needed
        if outfile is None:
            name = os.path.basename(infile)
            if name[:-4] == '.enc':
                outfile = infile[:-4]
            else:
                outfile = infile

        # Decrypt AES key if indicated
        if dec_aes_key:
            kh = KeyHandler()
            r = kh.load_key(path=inkey, key_type="PRIV",
                            encoding="PEM", ask_pass=has_pass)
            aes_key = self.decrypt_rsa(priv=r, ct=aes_key)

        # Read file and calculate bytes
        ct = int(readfile(filename=infile))
        b_ct = ct.to_bytes((ct.bit_length() + 7) // 8, 'big')

        # Decrypt ciphertext
        pt = self.decrypt_aesgcm(key=aes_key, nonce=nonce, aad=None, ct=b_ct)
        writefd(filename=outfile, content=pt.decode())
        Shell.rm(infile)
