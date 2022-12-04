# PasswordManager

## Installation

### Installation python:

You can file all documentation to install [Python](https://www.python.org/downloads/)

### Installation packages:

```sh
pip install -r requirements.txt
```

## Setup

- Create your private key:
```sh
python passwordManager.py -g
```

- Create your file with your passwords, you can see [passwords.txt](./passwords.txt) example.

## Usage

```sh

python passwordManager.py [OPTION] [FILE]
```


### Graphical Mode

```sh
python passwordManager.py --graphical
```

### Encrypt file

```sh

python passwordManager.py -e passwords.txt -p privatekey.ecc
```

### Decrypt file

```sh

python passwordManager.py -d passwords.txt -p privatekey.ecc
```

⚠️ Result print in your prompt.

### More information

You can use:
```
python passwordManager.py -h
```
