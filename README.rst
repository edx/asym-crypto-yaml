asym-crypto-yaml
================

Encrypt secrets in yaml alongside non secrets without changing the structure. Can be used as a cli tool or as a dependency.

Example:


    pip install asym-crypto-yaml

    asym_crypto_yaml --help

First we generate some keys, the public key is used for encryption, the private key is used for decryption
the private key is SECRET


    asym_crypto_yaml generate-private-key --private_key_output key.private

the public key IS NOT SECRET.

    asym_crypto_yaml generate-public-key --private_key_file key.private --public_key_output key.public

Say you have a yaml file named config.yml: 

    SOME_USERNAME: A
    SOME_HOSTNAME: B


You want to add a new key/value pair:

    SOME_PASSWORD: C


but you want it to be encrypted


    touch config.yml


Using your public key, which is not a secret, you can encrypt it like so:

    asym_crypto_yaml add-secret --yaml_key SOME_PASSWORD --public_key_file key.public --target_secret_file config.yml

    cat config.yml 


    | SOME_HOSTNAME: B
    | SOME_PASSWORD: !Encrypted |
    |   bftPXUsGT3f/dJKe7a1Cv1JHkTZyUjfZQAfw4I69RbzGKetRL7eg3Mb+8+zfSwD40ITpj8UC7R/8
    |   QUDflGxRLyBDP88mFU5W6S6ZkO+tDL9Z5KDDspGl/Fx6tyvFWld/ft9xFGE+hUaB8slgNXZL7sTf
    |   BG9ESd4cBy8pc3f3RQpLoft5EP+uywISxFPDsUAV4FcTSyBZhL6Nzo7U9QZy0A2pbFE18FxzzYX4
    |   6S6KOoZ51nJ21RZorrjgzZAo7PEc/7xHhriH1kJBZBOCyea6jLlLui/CzZm/j8sqACUAs97islE/
    |   n+/V3hkWHWmFD9KMFMm49nmvHPIjL/a57coYBWY0x+KNef6B5NyXFl39phx13QsyXlC64rlBNo7O
    |   U+isvGJhOh0IuoAnZqaQ0+VmTm/xJPgsbPzWi3UIJT8VXBM7odOhyX/Q904VrxTZmpUxwv1I3+/o
    |   cb54HlNE+7HTcxpRwMt6XbqRkbQ4lIEQp8wsRXRMgm6h6UxojNtOuvkdTJ3LgzKOVil99rjnsaBe
    |   cgmUq3+lyARXI3WHq01KVzY6nMbUJvIsW9A63SYjjFdqyW3nMOwyhi6c4jjdZmxGgyR9ndj56KCj
    |   Wyt9CVjQRo6EzAlKonE74X5ylcj7MQIgTfb5GNgD9djlttL0lYcqadZqSeagesdn/ZVFxB9tA1g=
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
    |       bftPXUsGT3f/dJKe7a1Cv1JHkTZyUjfZQAfw4I69RbzGKetRL7eg3Mb+8+zfSwD40ITpj8UC7R/8
    |       QUDflGxRLyBDP88mFU5W6S6ZkO+tDL9Z5KDDspGl/Fx6tyvFWld/ft9xFGE+hUaB8slgNXZL7sTf
    |       BG9ESd4cBy8pc3f3RQpLoft5EP+uywISxFPDsUAV4FcTSyBZhL6Nzo7U9QZy0A2pbFE18FxzzYX4
    |       6S6KOoZ51nJ21RZorrjgzZAo7PEc/7xHhriH1kJBZBOCyea6jLlLui/CzZm/j8sqACUAs97islE/
    |       n+/V3hkWHWmFD9KMFMm49nmvHPIjL/a57coYBWY0x+KNef6B5NyXFl39phx13QsyXlC64rlBNo7O
    |       U+isvGJhOh0IuoAnZqaQ0+VmTm/xJPgsbPzWi3UIJT8VXBM7odOhyX/Q904VrxTZmpUxwv1I3+/o
    |       cb54HlNE+7HTcxpRwMt6XbqRkbQ4lIEQp8wsRXRMgm6h6UxojNtOuvkdTJ3LgzKOVil99rjnsaBe
    |       cgmUq3+lyARXI3WHq01KVzY6nMbUJvIsW9A63SYjjFdqyW3nMOwyhi6c4jjdZmxGgyR9ndj56KCj
    |       Wyt9CVjQRo6EzAlKonE74X5ylcj7MQIgTfb5GNgD9djlttL0lYcqadZqSeagesdn/ZVFxB9tA1g=
    |  SOME_TOP_LEVEL_KEY:
    |    SOME_OTHER_PASSWORD: !Encrypted |
    |       bftPXUsGT3f/dJKe7a1Cv1JHkTZyUjfZQAfw4I69RbzGKetRL7eg3Mb+8+zfSwD40ITpj8UC7R/8
    |       QUDflGxRLyBDP88mFU5W6S6ZkO+tDL9Z5KDDspGl/Fx6tyvFWld/ft9xFGE+hUaB8slgNXZL7sTf
    |       BG9ESd4cBy8pc3f3RQpLoft5EP+uywISxFPDsUAV4FcTSyBZhL6Nzo7U9QZy0A2pbFE18FxzzYX4
    |       6S6KOoZ51nJ21RZorrjgzZAo7PEc/7xHhriH1kJBZBOCyea6jLlLui/CzZm/j8sqACUAs97islE/
    |       n+/V3hkWHWmFD9KMFMm49nmvHPIjL/a57coYBWY0x+KNef6B5NyXFl39phx13QsyXlC64rlBNo7O
    |       U+isvGJhOh0IuoAnZqaQ0+VmTm/xJPgsbPzWi3UIJT8VXBM7odOhyX/Q904VrxTZmpUxwv1I3+/o
    |       cb54HlNE+7HTcxpRwMt6XbqRkbQ4lIEQp8wsRXRMgm6h6UxojNtOuvkdTJ3LgzKOVil99rjnsaBe
    |       cgmUq3+lyARXI3WHq01KVzY6nMbUJvIsW9A63SYjjFdqyW3nMOwyhi6c4jjdZmxGgyR9ndj56KCj
    |       Wyt9CVjQRo6EzAlKonE74X5ylcj7MQIgTfb5GNgD9djlttL0lYcqadZqSeagesdn/ZVFxB9tA1g=
    |  SOME_USERNAME: A


The easiest way to do that is:


    asym_crypto_yaml encrypt-secret --public_key_file key.public

    |  !Encrypted | bftPXUsGT3f/dJKe7a1Cv1JHkTZyUjfZQAfw4I69RbzGKetRL7eg3Mb+8+zfSwD40ITpj8UC7R/8
    |  QUDflGxRLyBDP88mFU5W6S6ZkO+tDL9Z5KDDspGl/Fx6tyvFWld/ft9xFGE+hUaB8slgNXZL7sTf
    |  BG9ESd4cBy8pc3f3RQpLoft5EP+uywISxFPDsUAV4FcTSyBZhL6Nzo7U9QZy0A2pbFE18FxzzYX4
    |  6S6KOoZ51nJ21RZorrjgzZAo7PEc/7xHhriH1kJBZBOCyea6jLlLui/CzZm/j8sqACUAs97islE/
    |  n+/V3hkWHWmFD9KMFMm49nmvHPIjL/a57coYBWY0x+KNef6B5NyXFl39phx13QsyXlC64rlBNo7O
    |  U+isvGJhOh0IuoAnZqaQ0+VmTm/xJPgsbPzWi3UIJT8VXBM7odOhyX/Q904VrxTZmpUxwv1I3+/o
    |  cb54HlNE+7HTcxpRwMt6XbqRkbQ4lIEQp8wsRXRMgm6h6UxojNtOuvkdTJ3LgzKOVil99rjnsaBe
    |  cgmUq3+lyARXI3WHq01KVzY6nMbUJvIsW9A63SYjjFdqyW3nMOwyhi6c4jjdZmxGgyR9ndj56KCj
    |  Wyt9CVjQRo6EzAlKonE74X5ylcj7MQIgTfb5GNgD9djlttL0lYcqadZqSeagesdn/ZVFxB9tA1g=


Then just paste that in as the value anywhere within your yaml
