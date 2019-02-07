import yaml
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes
from asym_crypto_yaml import encrypted_representer, encrypted_constructor
from asym_crypto_yaml import decrypt_value, encrypt_value, Encrypted, encode, decode
from asym_crypto_yaml import load_private_key_from_file, load_public_key_from_file, generate_new_private_key
from asym_crypto_yaml import generate_new_public_key, check_key_length, configure_pyyaml, load
from asym_crypto_yaml import NUMBER_OF_BYTES_PER_ENCRYPTED_CHUNK, KEY_CHUNK_SIZE, SUPPORTED_KEY_SIZES


def test_crypto():
    configure_pyyaml()
    private_key = generate_new_private_key()
    public_key = generate_new_public_key(private_key)

    input_str = "AABB"

    encrypted_str = encrypt_value(input_str, public_key)

    built_dict  = {"sum_key": Encrypted(encrypted_str)}
    dump_output = yaml.safe_dump(built_dict)

    str_to_load = yaml.safe_dump(built_dict)
    load_output = yaml.safe_load(str_to_load)

    dump_output = yaml.safe_dump(load_output)

    load_output = yaml.safe_load(dump_output)
    parsed_encrypted = load_output['sum_key']

    output_str = decrypt_value(parsed_encrypted, private_key)

    assert input_str == output_str

def test_short_values():
    public_key = load_public_key_from_file('fixtures/test.public')
    input_str = "A" * 2

    message = encrypt_value(input_str, public_key)

    private_key = load_private_key_from_file('fixtures/test.private')

    output_str = decrypt_value(message, private_key)

    assert input_str == output_str

def test_supported_keys_and_generated_lengths():

    # Make sure that for all supported key lengths that
    # the generated encrypted blocks are of the correct length

    for key_length in SUPPORTED_KEY_SIZES:
        print("key length was: %s" % key_length)
        private_key = generate_new_private_key(key_length)
        public_key = generate_new_public_key(private_key)

        public_key = load_public_key_from_file('fixtures/test.public')

        # Encrypted blob of various lengths should be the same number of bytes
        input_str = "你" * 2
        output1 = encrypt_value(input_str, public_key).encode('utf-8')


        input_str = "C" * KEY_CHUNK_SIZE
        output2 = encrypt_value(input_str, public_key).encode('utf-8')

        input_str = "!" * (KEY_CHUNK_SIZE + 1)
        output3 = encrypt_value(input_str, public_key).encode('utf-8')

        input_str = "z" * (KEY_CHUNK_SIZE * 10)
        output4 = encrypt_value(input_str, public_key).encode('utf-8')

        assert len(output1) == len(output2)
        assert len(output1) == NUMBER_OF_BYTES_PER_ENCRYPTED_CHUNK
        assert len(output3) == NUMBER_OF_BYTES_PER_ENCRYPTED_CHUNK * 2
        assert len(output4) == NUMBER_OF_BYTES_PER_ENCRYPTED_CHUNK * 10


def test_long_values():
    public_key = load_public_key_from_file('fixtures/test.public')
    input_str = "你" * KEY_CHUNK_SIZE * 10
    private_key = load_private_key_from_file('fixtures/test.private')

    message = encrypt_value(input_str, public_key)
    output_str = decrypt_value(message, private_key)

    assert input_str == output_str

def test_load_with_no_key():
    """This should look like yaml.load"""
    assert load('some str') == 'some str'
    with open('fixtures/test.yml', "r") as f:
        loaded_dict = load(f)
        assert isinstance(loaded_dict['PASSWORD'], Encrypted)
    # It should also work with encrypted values, even if no key is passed
