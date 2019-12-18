import munch
import os
import oyaml as yaml
import re
import requests
import sys
import shutil
import tempfile

from base64 import b64encode, b64decode
from os import mkdir
from os.path import isfile, realpath, exists, dirname
from pathlib import Path
from shutil import copyfile, copy2

from cloudmesh.common.FlatDict import flatten
from cloudmesh.common.Shell import Shell
from cloudmesh.common.console import Console
from cloudmesh.common.dotdict import dotdict
from cloudmesh.common.util import backup_name
from cloudmesh.common.util import banner
from cloudmesh.common.util import path_expand
from cloudmesh.common.util import readfile
from cloudmesh.common.util import writefile
from cloudmesh.common.util import writefd
from cloudmesh.common.variables import Variables
from cloudmesh.common.FlatDict import FlatDict
from cloudmesh.configuration.security.CmsHasher import CmsHasher
from cloudmesh.configuration.security.KeyHandler import KeyHandler
from cloudmesh.configuration.security.CmsEncryptor import CmsEncryptor
from cloudmesh.configuration import __version__ as cloudmesh_yaml_version


# see also https://github.com/cloudmesh/client/blob/master/cloudmesh_client/cloud/register.py

class Active(object):

    def __init__(self, config_path='~/.cloudmesh/cloudmesh.yaml'):
        self.config = Config(config_path=config_path)

    def clouds(self):
        names = []
        entries = self.config["cloudmesh"]["cloud"]
        for entry in entries:
            if entries[entry]["cm"]["active"]:
                names.append(entry)
        if len(names) == 0:
            names = None
        return names


class Config(object):
    __shared_state = {}

    def __init__(self, config_path='~/.cloudmesh/cloudmesh.yaml',
                 encrypted=False):
        """
        Initialize the Config class.

        :param config_path: A local file path to cloudmesh yaml config
            with a root element `cloudmesh`.
            Default: `~/.cloudmesh/cloudmesh.yaml`
        """

        self.__dict__ = self.__shared_state
        if "data" not in self.__dict__:
            self.load(config_path=config_path)
            try:
                self.user = self["cloudmesh.profile.user"]
            except:
                pass

    @staticmethod
    def version():
        return cloudmesh_yaml_version

    @staticmethod
    def secrets():
        return [
            "AZURE_SUBSCRIPTION_ID",
            "AZURE_TENANT_ID",
            "AZURE_APPLICATION_ID",
            "AZURE_SECRET_KEY",
            "EC2_ACCESS_ID",
            "EC2_SECRET_KEY",
            "OS_PASSWORD",
            "OS_USERNAME",
            "OS_PROJECT_ID",
            "MONGO_PASSWORD",
            "MONGO_USERNAME",
            "password",
            "passwd",
            "project_id",
            "private_key_id",
            "private_key",
            "client_id",
            "client_x509_cert_url"
        ]

    @staticmethod
    def exceptions():
        return [
            "cloudmesh.version",
            "cloudmesh.security.publickey",
            "cloudmesh.security.privatekey",
            "cloudmesh.security.secpath",
            "cloudmesh.security.secrets",
            "cloudmesh.security.exceptions",
            "cloudmesh.data.mongo.MONGO_PORT",
            "cloudmesh.data.mongo.MONGO_HOST",
            "cloudmesh.data.mongo.LOCAL",
            "cloudmesh.data.mongo.MODE",
            "cloudmesh.data.mongo.MONGO_DBNAME"
        ]

    def fetch(self,
              url=None,
              destination=None):
        """

        fetches the cloudmesh yaml file and places it in the given
        destination dir

        :param url: The url of the cloudmesh.yaml file from github
        :param destination: The destination file. If not specified it is the
                             home dir.
        :return:
        """
        if url is None:
            url = "https://raw.githubusercontent.com/cloudmesh/cloudmesh-configuration/master/cloudmesh/configuration/etc/cloudmesh.yaml"
        if destination is None:
            destination = "~/.cloudmesh/cloudmesh.yaml"

        destination = path_expand(destination)

        Shell.mkdir("~/.cloudmesh")

        r = requests.get(url)
        content = r.text

        writefile(destination, content)

    def load(self, config_path='~/.cloudmesh/cloudmesh.yaml'):
        """
        loads a configuration file
        :param config_path:
        :type config_path:
        :return:
        :rtype:
        """

        # VERBOSE("Load config")

        self.config_path = str(Path(path_expand(config_path)).resolve())
        self.config_folder = dirname(self.config_path)

        self.create(config_path=config_path)

        with open(self.config_path, "r") as stream:
            content = stream.read()
            # content = path_expand(content)
            content = self.spec_replace(content)
            self.data = yaml.load(content, Loader=yaml.SafeLoader)

        # print (self.data["cloudmesh"].keys())

        # self.data is loaded as nested OrderedDict, can not use set or get
        # methods directly

        if self.data is None:
            raise EnvironmentError(
                "Failed to load configuration file cloudmesh.yaml, "
                "please check the path and file locally")

        #
        # populate default variables
        #

        self.variable_database = Variables(filename="~/.cloudmesh/var-data")
        self.set_debug_defaults()

        default = self.default()

        for name in self.default():
            if name not in self.variable_database:
                self.variable_database[name] = default[name]
        if "cloud" in default:
            self.cloud = default["cloud"]
        else:
            self.cloud = None

    def create(self, config_path='~/.cloudmesh/cloudmesh.yaml'):
        """
        creates the cloudmesh.yaml file in the specified location. The
        default is

            ~/.cloudmesh/cloudmesh.yaml

        If the file does not exist, it is initialized with a default. You still
        need to edit the file.

        :param config_path:  The yaml file to create
        :type config_path: string
        """
        self.config_path = Path(path_expand(config_path)).resolve()

        self.config_folder = dirname(self.config_path)

        if not exists(self.config_folder):
            mkdir(self.config_folder)

        if not isfile(self.config_path):
            source = Path(dirname(realpath(__file__)) + "/etc/cloudmesh.yaml")

            copyfile(source.resolve(), self.config_path)

            # read defaults
            self.__init__()

            defaults = self["cloudmesh.default"]

            # pprint(defaults)

            d = Variables()
            if defaults is not None:
                print("# Set default from yaml file:")

            for key in defaults:
                value = defaults[key]
                print("set {key}={value}".format(**locals()))
                d[key] = defaults[key]

    @staticmethod
    def check(path="~/.cloudmesh/cloudmesh.yaml"):

        error = False
        path = path_expand(path)

        banner("Check for Version")

        config = Config()

        dist_version = config.version()
        yaml_version = config["cloudmesh.version"]

        if dist_version == yaml_version:
            Console.ok(f"The version is {dist_version}")
        else:
            Console.error("Your version do not match")
            print()
            print("Found ~/.cloudmesh/cloudmesh.yaml:", yaml_version)
            print("Please update to version         :", dist_version)
            print("")
            print("See also: ")
            print()
            print(
                "  https://github.com/cloudmesh/cloudmesh-configuration/blob/master/cloudmesh/configuration/etc/cloudmesh.yaml")

        banner("Check for TAB Characters")

        error = Config.check_for_tabs(path)

        if not error:
            Console.ok("No TABs found")

        banner("yamllint")

        try:
            import yamllint

            options = \
                '-f colored ' \
                '-d "{extends: relaxed, ""rules: {line-length: {max: 256}}}"'
            r = Shell.live('yamllint {options} {path}'.format(**locals()))

            if 'error' in r or 'warning' in r:
                print(70 * '-')
                print(" line:column  description")
                print()
            else:
                Console.ok("No issues found")
                print()
        except:
            Console.error("Could not execute yamllint. Please add with")
            Console.error("pip install yamllint")

    @staticmethod
    def check_for_tabs(filename, verbose=True):
        """identifies if the file contains tabs and returns True if it
        does. It also prints the location of the lines and columns. If
        verbose is set to False, the location is not printed.

        :param verbose: if true prints issues
        :param filename: the filename
        :type filename: str
        :rtype: True if there are tabs in the file
        """
        filename = path_expand(filename)
        file_contains_tabs = False

        with open(filename, 'r') as f:
            lines = f.read().split("\n")

        line_no = 1
        for line in lines:
            if "\t" in line:
                file_contains_tabs = True
                location = [
                    i for i in range(len(line)) if line.startswith('\t', i)]
                if verbose:
                    Console.error(
                        "Tab found in line {line_no} and column(s) {location}"
                            .format(**locals()))
                    line_no += 1
        return file_contains_tabs

    def save(self, path="~/.cloudmesh/cloudmesh.yaml", backup=True):
        """
        #
        # not tested
        #
        saves th dic into the file. It also creates a backup if set to true The
        backup filename  appends a .bak.NO where number is a number that is not
        yet used in the backup directory.

        :param path:
        :type path:
        :return:
        :rtype:
        """
        path = path_expand(path)
        if backup:
            destination = backup_name(path)
            shutil.copyfile(path, destination)
        yaml_file = self.data.copy()
        with open(self.config_path, "w") as stream:
            yaml.safe_dump(yaml_file, stream, default_flow_style=False)

    def spec_replace(self, spec):

        # TODO: BUG: possible bug redundant char \{ in escape
        #            may be relevant for python 2 may behave differnet in
        #            differnt python versions, has to be checked. a unit test
        #            should be created to just check the \{ issue
        #
        variables = re.findall(r"\{\w.+\}", spec)

        for i in range(0, len(variables)):
            data = yaml.load(spec, Loader=yaml.SafeLoader)

            m = munch.DefaultMunch.fromDict(data)

            for variable in variables:
                text = variable
                variable = variable[1:-1]
                try:
                    value = eval("m.{variable}".format(**locals()))
                    if "{" not in value:
                        spec = spec.replace(text, value)
                except:
                    value = variable
        return spec

    def credentials(self, kind, name):
        """

        :param kind: the first level of attributes after cloudmesh
        :param name: the name of the resource
        :return:
        """
        return self.data["cloudmesh"][kind][name]["credentials"]

    # noinspection PyPep8Naming
    def check_for_TBD(self, kind, name):

        configuration = Config()["cloudmesh.{kind}.{name}".format(**locals())]

        result = {"cloudmesh": {"cloud": {name: configuration}}}

        banner("checking cloudmesh.{kind}.{name} in "
               "~/.cloudmesh/cloudmesh.yaml file".format(**locals()))

        print(yaml.dump(result))

        flat = flatten(configuration, sep=".")

        for attribute in flat:
            if "TBD" in str(flat[attribute]):
                Console.error(
                    "~/.cloudmesh.yaml: Attribute cloudmesh.{name}.{attribute} contains TBD".format(
                        **locals()))

    def set_debug_defaults(self):
        for name in ["trace", "debug"]:
            if name not in self.variable_database:
                self.variable_database[name] = str(False)

    def dict(self):
        return self.data

    def __str__(self):
        return self.cat_dict(self.data)

    @staticmethod
    def cat_dict(d,
                 mask_secrets=True,
                 attributes=None,
                 color=None):
        kluge = yaml.dump(d,
                          default_flow_style=False, indent=2)
        content = kluge.split("\n")

        return Config.cat_lines(content, mask_secrets=mask_secrets)

    @staticmethod
    def cat_lines(content,
                  mask_secrets=True,
                  attributes=None,
                  color=None):

        colors = ['TBD', "xxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", "12345", "xxxx"]
        if color:
            colors = colors + color

        secrets = Config.secrets()

        if attributes:
            secrets = secrets + attributes

        lines = []
        for line in content:
            if "TBD" not in line:
                if mask_secrets:
                    for attribute in secrets:
                        if attribute + ":" in line:
                            line = line.split(":")[0] + \
                                   Console.text(message=": '********'",
                                                color='BLUE')
                            break
            for colorme in colors:
                if colorme in line:
                    attribute, value = line.split(":", 1)
                    line = attribute + ":" + Console.text(color='RED',
                                                          message=value)

                    # line = line.replace(colorme,
                #                    Console.text(color='RED', message=colorme))

            lines.append(line)

        lines = '\n'.join(lines)
        return lines

    @staticmethod
    def cat(mask_secrets=True,
            attributes=None,
            path="~/.cloudmesh/cloudmesh.yaml",
            color=None):

        _path = path_expand("~/.cloudmesh/cloudmesh.yaml")
        with open(_path) as f:
            content = f.read().split("\n")
        return Config.cat_lines(content,
                                mask_secrets=mask_secrets,
                                attributes=None, color=None)

    def get(self, key, default=None):
        """
        A helper function for reading values from the config without
        a chain of `get()` calls.

        Usage:
            mongo_conn = conf.get('db.mongo.MONGO_CONNECTION_STRING')
            default_db = conf.get('default.db')
            az_credentials = conf.get('data.service.azure.credentials')

        :param default:
        :param key: A string representing the value's path in the config.
        """
        try:
            return self.__getitem__(key)
        except KeyError:
            if default is None:
                path = self.config_path
                Console.warning(
                    "The key '{key}' could not be found in the yaml file '{path}'".format(
                        **locals()))
                # sys.exit(1)
                raise KeyError(key)
            return default
        except Exception as e:
            print(e)
            sys.exit(1)

    def __setitem__(self, key, value):
        self.set(key, value)

    def set(self, key, value):
        """
        A helper function for setting the default cloud in the config without
        a chain of `set()` calls.

        Usage:
            mongo_conn = conf.set('db.mongo.MONGO_CONNECTION_STRING',
                         "https://localhost:3232")

        :param key: A string representing the value's path in the config.
        :param value: value to be set.
        """

        if value.lower() in ['true', 'false']:
            value = value.lower() == 'true'
        try:
            if "." in key:
                keys = key.split(".")
                #
                # create parents
                #
                parents = keys[:-1]
                location = self.data
                for parent in parents:
                    if parent not in location:
                        location[parent] = {}
                    location = location[parent]
                #
                # create entry
                #
                location[keys[len(keys) - 1]] = value
            else:
                self.data[key] = value

        except KeyError:
            path = self.config_path
            Console.error(
                "The key '{key}' could not be found in the yaml file '{path}'".format(
                    **locals()))
            sys.exit(1)
        except Exception as e:
            print(e)
            sys.exit(1)

        yaml_file = self.data.copy()
        with open(self.config_path, "w") as stream:
            yaml.safe_dump(yaml_file, stream, default_flow_style=False)

    def set_cloud(self, key, value):
        """
        A helper function for setting the default cloud in the config without
        a chain of `set()` calls.

        Usage:
            mongo_conn = conf.get('db.mongo.MONGO_CONNECTION_STRING',
                                  "https://localhost:3232")

        :param key: A string representing the value's path in the config.
        :param value: value to be set.
        """
        self.data['cloudmesh']['default']['cloud'] = value
        print("Setting env parameter cloud to: " +
              self.data['cloudmesh']['default']['cloud'])

        yaml_file = self.data.copy()
        with open(self.config_path, "w") as stream:
            print("Writing update to cloudmesh.yaml")
            yaml.safe_dump(yaml_file, stream, default_flow_style=False)

    def default(self):
        return dotdict(self.data["cloudmesh"]["default"])

    # def get(self, item):
    #     return self.__getitem__(item)

    def __getitem__(self, item):
        """
        gets an item form the dict. The key is . separated
        use it as follows get("a.b.c")
        :param item:
        :type item:
        :return:
        """
        try:
            if "." in item:
                keys = item.split(".")
            else:
                return self.data[item]
            element = self.data[keys[0]]
            for key in keys[1:]:
                element = element[key]
        except KeyError:
            path = self.config_path
            Console.warning(
                "The key '{item}' could not be found in the yaml file '{path}'".format(
                    **locals()))
            raise KeyError(item)
            # sys.exit(1)
        except Exception as e:
            print(e)
            sys.exit(1)
        # if element.lower() in ['true', 'false']:
        #    element = element.lower() == 'true'
        return element

    def __delitem__(self, item):
        """
        #
        # BUG THIS DOES NOT WORK
        #
        gets an item form the dict. The key is . separated
        use it as follows get("a.b.c")
        :param item:
        :type item:
        :return:
        """
        try:
            if "." in item:
                keys = item.split(".")
            else:
                return self.data[item]
            element = self.data
            print(keys)
            for key in keys:
                element = element[key]
            del element
        except KeyError:
            path = self.config_path
            Console.error(
                "The key '{item}' could not be found in the yaml file '{path}'".format(
                    **locals()))
            sys.exit(1)
        except Exception as e:
            print(e)
            sys.exit(1)

    def search(self, key, value):
        """
        search("cloudmesh.cloud.*.cm.active", True)
        :param key:
        :param value:
        :return:
        """
        flat = FlatDict(self.data, sep=".")
        result = flat.search(key, value)
        return result

    def edit(self, attribute):
        """
        edits the dict specified by the attribute and fills out all TBD values.
        :param attribute:
        :type attribute: string
        :return:
        """

        Console.ok("Filling out: {attribute}".format(attribute=attribute))

        try:
            config = Config()
            values = config[attribute]

            print("Editing the values for {attribute}"
                  .format(attribute=attribute))

            print("Current Values:")

            print(yaml.dump(values, indent=2))

            for key in values:
                if values[key] == "TBD":
                    result = input("Please enter new value for {key}: "
                                   .format(**locals()))
                    values[key] = result

            config.save()
        except Exception as e:
            print(e)
            Console.error(
                "could not find the attribute '{attribute}' in the yaml file."
                    .format(**locals()))

    def encrypt(self):
        """ 
        Encrypts the keys listed within Config.secrets()

        Assumptions:
            1. ```cms init``` or ```cms config secinit``` has been executed
            2. Private key is in PEM format
        """

        # Helper variables
        config = Config()
        ch = CmsHasher()  # Will hash the paths to produce file name
        kh = KeyHandler()  # Loads the public or private key bytes
        ce = CmsEncryptor()  # Assymmetric and Symmetric encryptor
        counter = 0

        # Create tmp file in case reversion is needed
        named_temp = tempfile.NamedTemporaryFile(delete=True)
        revertfd = open(named_temp.name,
                        'w')  # open file for reading and writing
        yaml.dump(self.data, revertfd)  # dump file in yaml format
        revertfd.close()  # close the data fd used to backup reversion file

        # Secinit variables: location where keys are stored
        secpath = path_expand(config['cloudmesh.security.secpath'])

        # Get the public key
        kp = config['cloudmesh.security.publickey']
        print(f"pub:{kp}")

        # Load the key with PEM or OpenSSH encoding
        pub = None
        try:
            Console.msg("Attempting to read key in PEM encoding")
            pub = kh.load_key(kp, "PUB", "PEM", False)
            Console.ok("Successfully loaded key")
        except ValueError:
            try:
                Console.msg("Attempting to read key in OpenSSH encoding")
                pub = kh.load_key(kp, "PUB", "SSH", False)
                Console.ok("Successfully loaded key")
            except ValueError:
                m = "Public key must be PEM or OpenSSH encoded"
                Console.error(f"{m}")
                sys.exit()
        except Exception as e:
            Console.error(f"{e.message}")
            sys.exit()

        # Get the regular expressions from config file
        try:
            paths = self.get_list_secrets()
            for path in paths:  # for each path that reaches the key
                # Hash the path to create a base filename
                # MD5 is acceptable since security does not rely on hiding path
                h = ch.hash_data(path, "MD5", "b64", True)
                fp = os.path.join(secpath, h)
                # Check if the attribute has already been encrypted
                if exists(f"{fp}.key"):
                    Console.ok(f"\tAlready encrypted: {path}")
                else:
                    counter += 1
                    Console.ok(f"\tencrypting: {path}")
                    # Additional Authenticated Data: the cloudmesh version
                    # number is used to future-proof for version attacks 
                    aad = config['cloudmesh.version']
                    b_aad = aad.encode()
                    b_aad = None

                    # Get plaintext data from config
                    pt = config[path]
                    if type(pt) != str:
                        pt = str(pt)

                    b_pt = pt.encode()

                    # Encrypt the cloudmesh.yaml attribute value
                    k, n, ct = ce.encrypt_aesgcm(data=b_pt, aad=b_aad)

                    # Write ciphertext contents
                    ct = int.from_bytes(ct, "big")
                    self.set(path, f"{ct}")

                    # Encrypt symmetric key with users public key
                    k_ct = ce.encrypt_rsa(pub=pub, pt=k)
                    # Write key to file
                    k_ct = b64encode(k_ct).decode()
                    fk = f"{fp}.key"  # use hashed filename with indicator
                    writefd(filename=fk, content=k_ct)

                    # Encrypt nonce with users private key
                    n_ct = ce.encrypt_rsa(pub=pub, pt=n)
                    # Write nonce to file
                    n_ct = b64encode(n_ct).decode()
                    fn = f"{fp}.nonce"
                    writefd(filename=fn, content=n_ct)

        except Exception as e:
            Console.error("reverting cloudmesh.yaml")
            # Revert original copy of cloudmesh.yaml
            copy2(src=named_temp.name, dst=self.config_path)
            named_temp.close()  # close (and delete) the reversion file

            # Delete generated nonces and keys
            for path in paths:
                # Calculate hashed filename
                h = ch.hash_data(path, "MD5", "b64", True)
                fp = os.path.join(secpath, h)

                # Remove key
                if os.path.exists(f"{fp}.key"):
                    os.remove(f"{fp}.key")

                # Remove nonce
                if os.path.exists(f"{fp}.nonce"):
                    os.remove(f"{fp}.nonce")
            sys.exit(f"{e}")

        named_temp.close()  # close (and delete) the reversion file
        Console.ok(f"Success: encrypted {counter} expressions")
        return counter

    def decrypt(self, ask_pass=True):
        """
        Decrypts all secrets within the config file

        Assumptions: please reference assumptions within encryption
                     section above
        """
        # Helper Classes 
        config = Config()
        ch = CmsHasher()  # Will hash the paths to produce file name
        kh = KeyHandler()  # Loads the public or private key bytes
        ce = CmsEncryptor()  # Assymmetric and Symmetric encryptor
        counter = 0

        # Create tmp file in case reversion is needed
        named_temp = tempfile.NamedTemporaryFile(delete=True)
        revertfd = open(named_temp.name, 'w')  # open file for writing
        yaml.dump(config.data, revertfd)  # dump file in yaml format
        revertfd.close()  # close the data fd used to backup reversion file

        # Secinit variables: location where keys are stored
        secpath = path_expand(config['cloudmesh.security.secpath'])

        # Load the private key
        kp = config['cloudmesh.security.privatekey']
        prv = kh.load_key(kp, "PRIV", "PEM", ask_pass)

        try:
            paths = self.get_list_secrets()
            for path in paths:  # for each path that reaches the key
                # hash the path to find the file name
                # MD5 is acceptable, attacker gains nothing by knowing path
                h = ch.hash_data(path, "MD5", "b64", True)
                fp = os.path.join(secpath, h)
                if not os.path.exists(f"{fp}.key"):
                    Console.ok(f"\tAlready plaintext: {path}")
                else:
                    counter += 1
                    Console.ok(f"\tDecrypting: {path}")
                    # Decrypt symmetric key, using private key
                    k_ct = readfile(f"{fp}.key")
                    b_k_ct = b64decode(k_ct)
                    b_k = ce.decrypt_rsa(priv=prv, ct=b_k_ct)

                    # Decrypt nonce, using private key
                    n_ct = readfile(f"{fp}.nonce")
                    b_n_ct = b64decode(n_ct)
                    b_n = ce.decrypt_rsa(priv=prv, ct=b_n_ct)

                    # Version number was used as aad
                    aad = config['cloudmesh.version']
                    b_aad = aad.encode()
                    b_aad = None

                    # Read ciphertext from config
                    ct = int(config[path])
                    b_ct = ct.to_bytes((ct.bit_length() + 7) // 8, 'big')

                    # Decrypt the attribute value ciphertext
                    pt = ce.decrypt_aesgcm(key=b_k, nonce=b_n, aad=b_aad,
                                           ct=b_ct)
                    pt = pt.decode()

                    # Set the attribute with the plaintext value
                    config.set(path, pt)
        except Exception as e:
            Console.error("reverting cloudmesh.yaml")
            copy2(src=named_temp.name, dst=config.config_path)
            named_temp.close()  # close (and delete) the reversion file
            sys.exit(f"{e}")

        for path in paths:
            h = ch.hash_data(path, "MD5", "b64", True)
            fp = os.path.join(secpath, h)
            os.remove(f"{fp}.key")
            os.remove(f"{fp}.nonce")

        named_temp.close()  # close (and delete) the reversion file

        Console.ok(f"Success: decrypted {counter} expressions")
        return counter

    def get_list_secrets(self):
        ret_list = []
        config = Config()

        # Retrieve the default secrets
        secexps = config.secrets()

        # Convert the defaults to regexps
        for i, e in enumerate(secexps):
            ne = ".*" + e + ".*"
            secexps[i] = ne

        # Get the regular expressions from config file
        usrexps = config['cloudmesh.security.secrets']

        # Append the defaults to the user define regular expressions
        for e in usrexps:
            secexps.append(e)

        # Get the cloudmesh defined regexps that prune the encryption list
        prnexps = config.exceptions()

        # Collect user defined list of regexps that prune the encryption list
        usrprn = config['cloudmesh.security.exceptions']
        for p in usrprn:
            prnexps.append(p)

        # Flatten the config data to get the dot path to all attributes
        flat_conf = flatten(config.data, sep='.')
        keys = flat_conf.keys()

        # for each of the expressions to encrypt the file
        for e in secexps:
            try: # Attempt to compile the secrets regexps
                r = re.compile(e)
                paths = list(filter(r.match, keys))
            except re.error as ex:
                Console.error(f"Invalid regexp {e}")
                sys.exit()
            except Exception as ex:
                Console.error(str(ex))
                sys.exit()

            # Prune the paths using cloudmesh.security.exceptions expressions
            # Note: cloudmesh.security.* should be matched its vital for enc/dec
            for pe in prnexps:
                try: # Attempt to compile the exceptions regexps
                    prn = re.compile(pe)
                    paths = list(filter(lambda i: not prn.match(i), paths))
                except re.error as ex:
                    Console.error(f"Invalid regexp {e}")
                    sys.exit()
                except Exception as ex:
                    Console.error(str(ex))
                    sys.exit()

            ret_list = ret_list + paths
        return list(set(ret_list))
