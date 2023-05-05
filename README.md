# ssh-keyfinder

ssh-keyfinder is a tool that automates the extraction of SSH private keys from ssh-agent. It can extract all keys at once and format them in OpenSSH format. Additionally, it can also extract private keys from a core dump and supports both ECDSA and RSA keys.

## Features

- Extracts SSH private keys from ssh-agent
- Can extract all keys at once
- Automatically formats keys in OpenSSH format
- Supports ECDSA and RSA keys
- Can reliably extract openssh private keys from a core dump

## Compatibility

ssh-keyfinder has been tested and confirmed to work on the following systems:

- Ubuntu 20.04 with OpenSSH V_8_4_P1 Linux 09a77df5423d 5.14.0-1050-oem #57-Ubuntu SMP Fri Aug 19 08:01:16 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
- Zorin OS 16.2 with OpenSSH_8.2p1 Linux sanctom 5.14.0-1050-oem #57-Ubuntu SMP Fri Aug 19 08:01:16 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux

## Usage

To extract SSH private keys from ssh-agent core dump, simply run the following command:

```
Usage: python3 ./ssh-keyfinder.py <ssh-agent> <coredump>
```

This will extract all private keys from ssh-agent and format them in OpenSSH format. The extracted keys will be displayed on the console.


Replace `<ssh-agent>` with the actual path to the ssh-agent binary file (the same version from the core dump).
Replace `<coredump>` with the actual path to the core dump file.


## Contribution

ssh-keyfinder is an open-source project, and contributions are welcome. If you encounter any bugs or issues, please report them on the project's [GitHub Issues](https://github.com/Kracken256/ssh-keyfinder/issues) page. If you would like to contribute code or documentation, please submit a pull request on the project's [GitHub repository](https://github.com/Kracken256/ssh-keyfinder).