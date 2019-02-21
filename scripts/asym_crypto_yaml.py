import click
import yaml
from base64 import b64encode
from asym_crypto_yaml import (Encrypted, decrypt_value, encrypt_value, load_public_key_from_file,
    load_private_key_from_file, load_private_key_from_string, generate_new_private_key,
    generate_new_public_key, write_public_key_to_file, write_private_key_to_file,
    add_secret_to_yaml_file, decrypt_yaml_dict, write_dict_to_yaml, generate_private_key_to_file,
    generate_public_key_to_file, encrypt_value_and_print, decrypt_yaml_file_and_write_encrypted_file_to_disk)

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
def add_secret(yaml_key, secret_contents, public_key_file, target_secret_file):
    add_secret_to_yaml_file(yaml_key, secret_contents, public_key_file, target_secret_file)

@click.command()
@click.option('--secrets_file_path', help='', default="config/config.yaml")
@click.option('--private_key_path', help='')
@click.option('--outfile_path', help='')
def decrypt_encrypted_yaml(secrets_file_path, private_key_path, outfile_path):
    decrypt_yaml_file_and_write_encrypted_file_to_disk(secrets_file_path, private_key_path, outfile_path)

cli.add_command(generate_private_key)
cli.add_command(generate_public_key)
cli.add_command(add_secret)
cli.add_command(encrypt_secret)
cli.add_command(decrypt_encrypted_yaml)

if __name__ == '__main__':
    cli()
