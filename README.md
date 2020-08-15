# Breaking Cryptography

This repository currently is being developed while I work on the [cryptopals crypto challenges](http://cryptopals.com) which are about breaking cryptographic systems.

While solving the challenges I'm developing the python package 'drvn.cryptography' which contains cryptography utility functions and methods to exploit cryptographic systems.

Here is a quick summary of what kind of exploits I have worked on in the challenges:

1. A method to decrypt any english text that has been encrypted using repeating-key XOR using an unknown key.
2. Detect if ciphertext is AES EBC encrypted.
3. Decrypt unknown_plaintext with repeated calls to an API like:
AES_ECB_ENCRYPT(attacker_controlled_bytes + unknown_plaintext, unknown_key)

## Usage

```
drvn_cryptography_run_cryptopals_challenge --help
```

## Installing

### Installing in editable-mode

```
sudo -H python3.8 -m pip install --editable .
```

### Installing in the usual, non-editable mode
```
python3.8 -m pip install --user drvn.cryptography
```

## Testing

### Testing prerequisites

```
python3.8 -m pip install --user --upgrade tox
python3.8 -m pip install --user --upgrade setuptools
```

### Running all tests

Runs unit- and integration tests using multiple python versions (specified by tox.ini's envlist)

```
tox
```

To get test coverage report you can try this (you need pytest and pytest-cov installed):

```
python3.8 -m pytest --cov=src/drvn --cov-report=html --cov-report=term --no-cov-on-fail tests
```

### Running unit tests

```
tox -e unit
```

### Running integration tests

```
tox -e integration
```

## Uploading

### Uploading prerequsites

```
python3.8 -m pip install --user -r requirements.txt
```

### Uploading to PyPi

```
./scripts/upload_package.py
```
