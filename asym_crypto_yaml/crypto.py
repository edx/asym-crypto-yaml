import yaml
import base64
from collections import OrderedDict
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes

# Magic numbers
KEY_CHUNK_SIZE = 100
SUPPORTED_KEY_SIZES = [2048, 4096]
NUMBER_OF_BYTES_PER_ENCRYPTED_CHUNK = 693

def _encode(b):
    """“Base64-encode a byte string, returning unicode, 
    this is done so that when pyyaml represents the Encrypted class instance it will look nice"""
    return base64.encodebytes(b).decode('ascii')

def _decode(s):
    """Inverse of encode, takes a unicode string and returns Base-64 bytes"""
    return base64.decodebytes(s.encode('ascii'))


class Encrypted(str):
    """Subclassing str is used to deserialize a Encrypted object so we can easily 
    tell between which values are encrypted and not encrypted when we do _safe_load
    this may cause problems, such as using toLower() will result in a str, not an Encrypted.
    When a correct key is passed these will be stripped out by decrypt_value
    See: https://pyyaml.org/wiki/PyYAMLDocumentation
    """
    def __new__(self, value):
        return str.__new__(self, value)
    def __repr__(self):
        return "!Encrypted %s " % self

def _encrypted_constructor(loader, node):
    """
    Used to tell pyyaml how to convert a string to an Encrypted class instance
    See: https://pyyaml.org/wiki/PyYAMLDocumentation
    """
    value = loader.construct_scalar(node)
    return Encrypted(value)

def _encrypted_representer(self, data):
    """
    Used to tell pyyaml how to represent a Encrypted class instance as a string
    See: https://pyyaml.org/wiki/PyYAMLDocumentation
    """
    return self.represent_scalar('!Encrypted', data, style='|')

    """
    Used to tell pyyaml how to convert a string to an dict class instance while preserving order
    See: https://pyyaml.org/wiki/PyYAMLDocumentation
    """
def _dict_representer(dumper, data):
    return dumper.represent_dict(getattr(data, "items")())

    """
    Used to tell pyyaml how to represent a dict as a string while preserving order
    See: https://pyyaml.org/wiki/PyYAMLDocumentation
    """
def _dict_constructor(loader, node):
    loader.flatten_mapping(node)
    pairs = loader.construct_pairs(node)
    try:
        return OrderedDict(pairs)
    except TypeError:
        loader.construct_mapping(node)
    raise

def _configure_pyyaml():
    """ 
    Internal call to configures the various representers/constructors
    used to ensure order is preserved in dictionaries and to yell pyYaml how to serialize and deserialize 
    encrypted values
    """
    yaml.SafeLoader.add_constructor(u'!Encrypted', _encrypted_constructor)
    yaml.SafeDumper.add_representer(Encrypted, _encrypted_representer)
    yaml.add_representer(dict, _dict_representer, Dumper=yaml.SafeDumper)
    yaml.add_representer(OrderedDict, _dict_representer, Dumper=yaml.SafeDumper)
    for loader_name in yaml.loader.__all__:
        Loader = getattr(yaml.loader, loader_name)
        yaml.add_constructor("tag:yaml.org,2002:map", _dict_constructor, Loader=Loader)

def _safe_load(input):
    """
    Ensures pyyaml is configured before calling safe_load
    """
    _configure_pyyaml()
    return yaml.safe_load(input)

def _safe_dump(input, f=None, default_flow_style=False):
    """
    Ensures pyyaml is configured before calling safe_dump
    allows additional args
    """
    _configure_pyyaml()
    return yaml.safe_dump(input, f, default_flow_style=default_flow_style)

def check_key_length(public_or_private_key):
    """
    Used to ensure this library is only used with key sizes that have tests
    this is done because of how we chunk and encrypt large values
    due to the max size that we can encrypt due to the algorithm chosen and the key size.
    """
    assert public_or_private_key.key_size in SUPPORTED_KEY_SIZES

def encrypt_value(str_input, public_key):
    """
    Takes a string and returns an Encrypted class instance whose value is the encrypted byte string
    """
    check_key_length(public_key)
    aggregate = ""
    chunks = chunk_input(str_input, KEY_CHUNK_SIZE)
    for chunk in chunks:
        encrypted_chunk = _encode(public_key.encrypt(
            chunk.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ))
        aggregate += encrypted_chunk
    return Encrypted(aggregate)


def decrypt_value(input, private_key):
    """
    Takes an Encrypted class instance and returns a string, if it can be decrypted, or the encrypted class instance, if no key is passed.
    If a key is passed and it cannot be used to decrypt the Encrypted class instance's value, it will throw an error.
    """
    check_key_length(private_key)
    if isinstance(input, Encrypted):
        aggregate = ""
        chunks = chunk_input(input, NUMBER_OF_BYTES_PER_ENCRYPTED_CHUNK)
        for chunk in chunks:
            aggregate += private_key.decrypt(
            _decode(chunk),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )).decode('utf-8')
        return aggregate
    else:
        return input

def chunk_input(inp, number_of_characters_per_string):
    """
    Breaks an input string inp into chunks of up to number_of_characters_per_string
    """
    # For item i in a range that is a length of l,
    for i in range(0, len(inp), number_of_characters_per_string):
        # Create an index range for l of n items:
        yield inp[i:i+number_of_characters_per_string]

def load_public_key_from_file(filepath):
    """
    Loads a public key from a file
    """
    with open(filepath, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    return public_key


def load_private_key_from_string(input):
    """
    Loads a private key from a string
    """
    private_key = serialization.load_pem_private_key(
        input,
        password=None,
        backend=default_backend()
    )
    return private_key


def load_private_key_from_file(filepath):
    """
    Loads a private key from a file
    """
    with open(filepath, "rb") as key_file:
        private_key = load_private_key_from_string(key_file.read())
    return private_key


def generate_new_private_key(key_size=4096):
    """
    Loads a private key of a keysize specified, if it is a keysize for which we do not have tests
    throw an exception
    """
    key = rsa.generate_private_key(
        # Dont change the exponent - see docs https://cryptography.io/en/latest/
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    check_key_length(key)
    return key

def generate_new_public_key(private_key):
    """
    Loads a public key using a given private key, if the key length
    of either is not a length for which we have tests, throw an exception
    """
    check_key_length(private_key)
    public_key = private_key.public_key()
    check_key_length(public_key)
    return public_key


def write_public_key_to_file(key, outfile):
    """
    Writes a public key to a file
    """
    with open(outfile, "wb") as f:
        f.write(key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))


def write_private_key_to_file(key, outfile):
    """
    Writes a private key to a file
    """
    with open(outfile, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),  # No passphrase
        ))

def decrypt_yaml_dict(input_dict, private_key):
    """
    Decrypts and removes all the encrypted class instances in a yaml file.
    It will return them instead of no key is passed.
    if the key is wrong, it will throw an exception.
    """
    decrypted_dict = {}
    for key, value in input_dict.items():
        if isinstance(value, dict):
            value = decrypt_yaml_dict(value, private_key)

        elif isinstance(value,list):
            decrypted_list = []
            for item in value:
                if isinstance(item, dict):
                    item = decrypt_yaml_dict(item, private_key)
                    decrypted_list.append(item)
                else:
                    if private_key is None:
                        decrypted_list.append(item)
                    else:
                        item = decrypt_value(item, private_key)
                        decrypted_list.append(item)
            value = decrypted_list

        if private_key is None:
            # Cannot decrypt, as we do not have a key, so just return
            # the value.  It will be a string or an Encrypted class instance depending on if it was encrypted or not.
            decrypted_dict[key] = value
        else:
            decrypted_dict[key] = decrypt_value(value, private_key)
    return decrypted_dict

def safe_load(input, private_key_file=None):
    """
    Configures pyyaml to deserialize Encrypted class instances, then calls decrypt_yaml_dict
    with a private key. 
    Decrypts and removes all the encrypted class instances in a yaml file.
    It will return them instead of no key is passed.
    if the key is wrong, it will throw an exception.
    """
    loaded_input = _safe_load(input)
    if not isinstance(loaded_input, dict):
        return loaded_input
    private_key = None
    if private_key_file is not None:
        private_key = load_private_key_from_file(private_key_file)
    return decrypt_yaml_dict(loaded_input, private_key)

def load(input, private_key_file=None):
    return safe_load(input, private_key_file)

def safe_dump(input_dict):
    """
    Wrapper for asym_crypto_yaml.dump which calls yaml.safe_dump
    """
    return dump(input_dict)

def dump(input_dict):
    """
    dumps a dict, converting it to a string, exists so this can be used as a dropin more easily for pyyaml
    """
    return _safe_dump(input_dict)

def write_dict_to_yaml(input_dict, outfile):
    """
    dumps a dict to a file
    """
    with open(outfile, "w") as f:
        _safe_dump(input_dict, f, default_flow_style=False)

def add_secret_to_yaml_file(yaml_key, yaml_value_unencrypted, public_key_file, yaml_file_to_append_to):
    """
    Loads a yaml dict from a file, encrypts a value and adds it to that dict,
    then dumps it back out to the same file
    """
    public_key = load_public_key_from_file(public_key_file)
    encrypted = encrypt_value(yaml_value_unencrypted, public_key)
    with open(yaml_file_to_append_to, "r") as f:
        encrypted_dict = _safe_load(f)
    if encrypted_dict is None:
        encrypted_dict = {}
    encrypted_dict[yaml_key] = encrypted
    write_dict_to_yaml(encrypted_dict, yaml_file_to_append_to)

def reencrypt_secrets(input_dict, private_key, public_key):
    """
    Re-encrypt all secrets in a yaml file.
    """
    encrypted_dict = {}
    for key, value in input_dict.items():
        if isinstance(value, dict):
            value = reencrypt_secrets(value, private_key, public_key)

        elif isinstance(value,list):
            encrypted_list = []
            for item in value:
                if isinstance(item, dict):
                    item = reencrypt_secrets(item, private_key, public_key)
                    encrypted_list.append(item)
                else:
                    if isinstance(item, Encrypted):
                        unencrypted_item = decrypt_value(item, private_key)
                        encrypted_item = encrypt_value(unencrypted_item, public_key)
                        encrypted_list.append(encrypted_item)
                    else:
                        encrypted_list.append(item)
            value = encrypted_list

        if isinstance(value, Encrypted):
            yaml_value_unencrypted = decrypt_value(value, private_key)
            encrypted = encrypt_value(yaml_value_unencrypted, public_key)
            encrypted_dict[key] = encrypted
        else:
            encrypted_dict[key] = value
    return encrypted_dict

def generate_private_key_to_file(outfile_path):
    """ Convenience method used by cli """
    private_key = generate_new_private_key()
    write_private_key_to_file(private_key, outfile_path)
    return private_key

def generate_public_key_to_file(private_key_file_path, public_key_file_output_path):
    """ Convenience method used by cli """
    private_key = load_private_key_from_file(private_key_file_path)
    public_key = generate_new_public_key(private_key)
    write_public_key_to_file(public_key, public_key_file_output_path)
    return public_key

def encrypt_value_and_print(unencrypted_value, public_key_file):
    public_key = load_public_key_from_file(public_key_file)
    encrypted_value = encrypt_value(unencrypted_value, public_key)
    print(_safe_dump(encrypted_value))
    return encrypted_value

def decrypt_yaml_file_and_write_encrypted_file_to_disk(input_yaml_file_path, private_key_path, output_yaml_file_path):
    private_key = None
    if private_key_path is not None:
        private_key = load_private_key_from_file(private_key_path)
    with open(input_yaml_file_path, "r") as f:
        encrypted_secrets = _safe_load(f)
    decrypted_secrets_dict = decrypt_yaml_dict(encrypted_secrets, private_key)
    write_dict_to_yaml(decrypted_secrets_dict, output_yaml_file_path)

def reencrypt_secrets_and_write_to_yaml_file(input_yaml_file_path, private_key_path, public_key_path):
    private_key = None
    public_key = None
    if private_key_path and public_key_path is not None:
        private_key = load_private_key_from_file(private_key_path)
        public_key = load_public_key_from_file(public_key_path)
    with open(input_yaml_file_path, "r") as f:
        encrypted_secrets = _safe_load(f)
    encrypted_secrets_dict = reencrypt_secrets(encrypted_secrets, private_key, public_key)
    write_dict_to_yaml(encrypted_secrets_dict, input_yaml_file_path)
