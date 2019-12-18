import sys
from base64 import b64encode
from cloudmesh.common.console import Console
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

class CmsHasher:
    def __init__(self, data=None, data_type=str):
        # Check if data is empty
        if data is not None:
            # Ensure proper data type
            if data_type is str:
                self.data = data.encode()
            elif data_type is bytes:
                self.data = data
            else:
                Console.error(f"data_type:{data_type} is not supported")
                sys.exit()

    def hash_data(self, data=None, hash_alg="SHA256"
                  , encoding=False, clean=False):
        digest = None
        if hash_alg == "MD5":
            # !!!!!!!!!!!!!!!!!!!!!!! Warning !!!!!!!!!!!!!!!!!!!!!!!!
            # This hash has know vulnerabilities. 
            # ONLY used this when the data does not need to be secert. 
            # !!!!!!!!!!!!!!!!!!!!!!! Warning !!!!!!!!!!!!!!!!!!!!!!!!
            digest = hashes.Hash(hashes.MD5(), backend=default_backend())
        elif hash_alg == "SHA256":
            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        else:
            Console.error("Unsupported Hashing algorithm")
            sys.exit()

        if type(data) is str:
            data = data.encode()
        digest.update(data)
        hashed = digest.finalize()

        # Encode data if requested
        if not encoding:
            """no op, just for check"""
        elif encoding == "b64":
            hashed = b64encode(hashed).decode()
        else:
            Console.error("Unknown encoding requested")
            sys.exit()

        # Clean data for system purposes if requested
        if clean:
            remove_chars = ['+', '=', '\\',
                            '/']  # special dir chars on typical os
            for char in remove_chars:
                if char in hashed:
                    hashed = hashed.replace(char, "")

        return hashed
