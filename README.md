# Cryptography

## Usage

```
svarmi_cryptography --help
```

## Installing

### Installing prerequsites

Run [this](https://gitlab.com/svarmi/scripts/-/blob/master/configure_authentication_to_spypi.py) script to configure authentication to SPyPi.

### Installing in editable-mode

```
sudo -H python3.8 -m pip install --editable .
```

### Installing in the usual, non-editable mode
```
python3.8 -m pip install --user --index-url https://${SPYPI_USERNAME}:${SPYPI_PASSWORD}@spypi.svarmi.is svarmi.cryptography
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

Run [this](https://gitlab.com/svarmi/scripts/-/blob/master/configure_authentication_to_spypi.py) script to configure authentication to SPyPi.

```
python3.8 -m pip install --user -r requirements.txt
```

### Uploading to SPyPi

After editing package version in setup.py adhering to [semantic versioning](https://semver.org/), run the following to upload your package to SPyPi:

```
tox -e upload
```

Copyright (C) 2020, Svarmi
All rights reserved.
