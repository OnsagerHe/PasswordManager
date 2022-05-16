# PasswordManager

## Installation

You can file all documentation to install [Python](https://www.python.org/downloads/)

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

### Encrypt file

```sh

python passwordManager.py -e passwords.txt
```

### Decrypt file

```sh

python passwordManager.py -d passwords.txt
```

⚠️ Result print in your prompt.
