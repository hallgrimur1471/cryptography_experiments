# Cryptography

Library developed while attempting the [cryptopals crypto challenges](http://cryptopals.com)

## Usage

```
drvn_cryptography --help
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
