import hashlib
import sys

import click
import yaml
from base64 import b64encode
from asym_crypto_yaml import *

# Please make additional commands added to the cli a single function call and provide a test case.

@click.group()
def cli():
    pass

@click.command()
@click.option('--private_key_output', help="File to write the private key to.  Do not commit this or share it with anyone", required=True)
def generate_private_key(private_key_output):
    generate_private_key_to_file(private_key_output)

@click.command()
@click.option('--private_key_file', help="Private key to use to generate a new public key.  Do not commit this or share it with anyone", required=True)
@click.option('--public_key_output', help="Public key output, should probably be included in the repo", required=True)
def generate_public_key(private_key_file, public_key_output):
    generate_public_key_to_file(private_key_file, public_key_output)

@click.command()
@click.option('--secret_contents', prompt=True, hide_input=True)
@click.option('--public_key_file', default="clamps.public")
def encrypt_secret(secret_contents, public_key_file):
    encrypt_value_and_print(secret_contents, public_key_file)

@click.command()
@click.option('--yaml_key', required=True)
@click.option('--secret_contents', prompt=True, hide_input=True)
@click.option('--public_key_file', default="clamps.public")
@click.option('--target_secret_file', default="config/secrets.yaml")
@click.option('--print-hash/--no-print-hash', default=False, help="Print a hash of the secret for verification of correct typing/pasting")
def add_secret(yaml_key, secret_contents, public_key_file, target_secret_file, print_hash):
    add_secret_to_yaml_file(yaml_key, secret_contents, public_key_file, target_secret_file)
    if print_hash:
        sec_hash = hashlib.sha256(secret_contents.encode()).hexdigest()
        print("SHA256 hash of secret: %s" % sec_hash, file=sys.stderr)

@click.command()
@click.option('--secrets_file_path', help='', default="config/config.yaml")
@click.option('--private_key_path', help='')
@click.option('--outfile_path', help='')
def decrypt_encrypted_yaml(secrets_file_path, private_key_path, outfile_path):
    decrypt_yaml_file_and_write_encrypted_file_to_disk(secrets_file_path, private_key_path, outfile_path)


@click.command()
@click.option('--secrets_file_path', help='', default="config/config.yaml")
@click.option('--private_key_path', help='Old Private Key to decrypt the encrypted secrets in yaml file')
@click.option('--public_key_path', help='New Public Key to re-encrypt the secrets in yaml file')
def reencrypt_yaml(secrets_file_path, private_key_path,public_key_path):
    reencrypt_secrets_and_write_to_yaml_file(secrets_file_path, private_key_path, public_key_path)

@click.command()
@click.option('--secrets_dir_path', help='', default="config/config.yaml")
@click.option('--private_key_path', help='Old Private Key to decrypt the encrypted secrets in yaml file')
@click.option('--public_key_path', help='New Public Key to re-encrypt the secrets in yaml file')
@click.option('--old-secret', prompt=True, hide_input=True)
@click.option('--new-secret', prompt=True, hide_input=True)
def rotate_secret(secrets_dir_path, private_key_path, public_key_path, old_secret, new_secret):
    rotate_secrets_and_write_to_yaml_file(secrets_dir_path, private_key_path, public_key_path, old_secret, new_secret)


cli.add_command(generate_private_key)
cli.add_command(generate_public_key)
cli.add_command(add_secret)
cli.add_command(encrypt_secret)
cli.add_command(decrypt_encrypted_yaml)
cli.add_command(reencrypt_yaml)
cli.add_command(rotate_secret)

if __name__ == '__main__':
    cli()
