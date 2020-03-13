# ReadPE

A cross platform tool to work with PE files from the command line.

# 

# Installation

- Using `pip`

```
$ pip install readpe
```

- From `source`

```
$ git clone https://github.com/N1ght-W0lf/readpe
$ cd readpe
$ python setup.py install
```

# Usage

```
usage: readpe <pefile> <options>

Display information about the contents of PE files

positional arguments:
  pefile                 PE file path

optional arguments:
  -H, --all-headers      Display all PE headers
  -d, --dos-header       Display the PE DOS header
  -h, --file-header      Display the PE File header
  -o, --optional-header  Display the PE Optional header
  -D, --dirs             Display the PE Data Directories
  -i, --imports          Display imported functions
  -e, --exports          Display exported functions
  -s, --sections         Display all sections headers
  -r, --resources        Display all resources
  -x, --extract          Extract resources
  -t TYPE, --type TYPE   Resource type to dump
  -n NAME, --name NAME   Resource name to dump
  --help                 Display this help

Example: readpe test.exe -d -h -o
```

# 

# License

```
Copyright (c) 2020 N1ght-W0lf - Released under MIT License
```

