# PasswordManager

## Installation

You can file all documentation to install [Python](https://www.python.org/downloads/)

## Setup

- Create your private key:
```py
python passwordManager.py -g
```

- Create your file with your passwords, you can see [passwords.txt](./passwords.txt) example.

## Usage

```py

python passwordManager.py [OPTION] [FILE]
```

### Encrypt file

```py

python passwordManager.py -e passwords.txt
```

### Decrypt file

```py

python passwordManager.py -d passwords.txt
```

⚠️ Result print in your prompt.
