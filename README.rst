asym-crypto-yaml
================

.. image:: https://api.travis-ci.org/edx/asym-crypto-yaml.svg



Encrypt secrets in YAML alongside non secrets in YAML. Can be used as a cli tool or as a dependency.

Installation
-------------

    pip install asym-crypto-yaml


Cli Usage
-------------

    asym_crypto_yaml --help

First we generate some keys, the public key is used for encryption, the private key is used for decryption
the private key is SECRET

the public key IS NOT SECRET.

    asym_crypto_yaml generate-private-key --private_key_output key.private

    asym_crypto_yaml generate-public-key --private_key_file key.private --public_key_output key.public

Say you have a yaml file named config.yml: 

    SOME_USERNAME: A
    
    SOME_HOSTNAME: B


You want to add a new key/value pair:

    SOME_PASSWORD: C

but you want 'C' to be encrypted

Using your public key, which is not a secret, you can encrypt it like so:

    asym_crypto_yaml add-secret --yaml_key SOME_PASSWORD --public_key_file key.public --target_secret_file config.yml

    cat config.yml 


    | SOME_HOSTNAME: B
    | SOME_PASSWORD: !Encrypted |
    |   AABBCCDDZZZZZ
    | SOME_USERNAME: A



Then unencrypt it like so:

asym_crypto_yaml decrypt-encrypted-yaml --secrets_file_path config.yml --private_key_path key.private --outfile_path unencrypted_config.yml

cat unencrypted_config.yml 

    SOME_HOSTNAME: B
    SOME_PASSWORD: C
    SOME_USERNAME: A


If you want to do nested keys you will need to paste them in yourself(for now):


    |  SOME_HOSTNAME: B
    |  SOME_PASSWORD: !Encrypted |
    |   AABBCCDDZZZZZ
    |  SOME_TOP_LEVEL_KEY:
    |    SOME_OTHER_PASSWORD: !Encrypted |
    |       AABBCCDDZZZZZ
    |  SOME_USERNAME: A


The easiest way to do that is:


    asym_crypto_yaml encrypt-secret --public_key_file key.public

    |  !Encrypted | AABBCDDZZZZZ


Then just paste that in as the value anywhere within your yaml

Python Usage
-------------

You can install asym_crypto_yaml as a dependency and and accomplish all of the clis functionality via the python API.

    from asym_crypto_yaml import generate_private_key_to_file, generate_public_key_to_file,add_secret_to_yaml_file
    
    private_key = generate_private_key_to_file(private_key_output_filename)
    public_key = generate_public_key_to_file(private_key_output_filename, public_key_output_filename)
    add_secret_to_yaml_file(test_key_value, test_key_value, public_key_output_filename, yaml_file_to_append_to)

See test_crypto.py for more examples.


Docker Usage
-------------
The cli is published to Dockerhub as a docker image
You can generate a public and private key in your current directory like so:
    
    docker run -it --rm -v $(pwd):/asym -w /asym asym_crypto_yaml generate-private-key --private_key_output key.private
    docker run -it --rm -v $(pwd):/asym -w /asym asym_crypto_yaml generate-public-key --private_key_file key.private --public_key_output key.public
    
Any other cli commands can be run in this fashion.
    
    
Tests(in docker)
-------------

Install docker first then:

    make test
    
    
Tests(out of docker)
-------------

Make sure you are using python > 3.6 then

    pip install -r requirements/development.txt
    
    make run-tests

    
Deveopment(in docker)
-------------
This will give you a shell with access to the cli that hotreloads your code changes in your editor, clone the repo then do:
    
    make build-docker shell
    
If you just type 'make' a help document will be printed which will show you the available commands.
    
    
Update requirements
----------------------
Doing this will spin up the docker dev environment and update the requirements

    make upgrade
    
