# ssh-keyfinder

ssh-keyfinder is a tool that automates the extraction of SSH private keys from ssh-agent. It can extract all keys at once and format them in OpenSSH format. Additionally, it supports ALL SSH private key formats including RSA, ECDSA, and DSA.

## Features

- Extracts SSH private keys from ssh-agent
- Simple CLI interface
- Can extract all keys at once
- Automatically formats keys in OpenSSH format
- Supports RSA, ECDSA, and DSA keys
- Can reliably extract openssh private keys from a core dump

## Compatibility

ssh-keyfinder has been tested and confirmed to work on the following systems:

- Ubuntu 20.04 with OpenSSH V_8_4_P1 Linux 09a77df5423d 5.14.0-1050-oem #57-Ubuntu SMP Fri Aug 19 08:01:16 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
- Zorin OS 16.2 with OpenSSH_8.2p1 Linux sanctom 5.14.0-1050-oem #57-Ubuntu SMP Fri Aug 19 08:01:16 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux


## Docker setup
I including a docker image file for reliable usage. 
To run this script in Docker run the following commands:
```sh
# To build for Docker
cd <git clone directory>
docker build -t ssh-keyfinder:2.0 .

# To run in docker
docker run -it -v <directory with core dumps>:/opt/data ssh-keyfinder:2.0 bash

# Run all the following commands in Docker
# Copy your core dump to docker working dir
cp <directory with core dumps>/<core dump name> /opt/ssh-keyfinder

# Extract keys from core dump
/opt/ssh-keyfinder.py <core dump name>

# If it worked your private keys will be printed to the console
```

Replace the `<git clone directory>` with te directory where to downloaded the source code.
Replace `<directory with core dumps>` with the absolute folder path of a directory containing the core dump you want to extract private keys from.
Replace `<core dump name>` with the name of your core dump file. Example: `core.1324`

## Usage

To extract SSH private keys from ssh-agent core dump, simply run the following command:

```
Usage: python3 ./ssh-keyfinder.py <coredump file>
```

This will extract all private keys from ssh-agent and format them in OpenSSH format. The extracted keys will be displayed on the console.


Replace `<coredump>` with the actual path to the core dump file.


## Contribution

ssh-keyfinder is an open-source project, and contributions are welcome. If you encounter any bugs or issues, please report them on the project's [GitHub Issues](https://github.com/Kracken256/ssh-keyfinder/issues) page. If you would like to contribute code or documentation, please submit a pull request on the project's [GitHub repository](https://github.com/Kracken256/ssh-keyfinder).