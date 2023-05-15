# OpenSSH private key extractor

ssh-keyfinder is a tool that automates the extraction of SSH private keys from ssh-agent. It can extract all keys at once and format them in OpenSSH format. Additionally, it supports ALL SSH private key formats including RSA, ECDSA, and DSA.

## Features
- Simple WebUI frontend interface
- Extracts SSH private keys from ssh-agent core dump
- Simple CLI interface
- Can extract all keys at once
- Automatically formats keys in OpenSSH format
- Supports RSA, ECDSA, and DSA keys
- Modern colorful UI with tailwindcss

## Compatibility

ssh-keyfinder has been tested and confirmed to work on these version of OpenSSH:

- OpenSSH_8.4p1
- OpenSSH_8.2p1

Did not work these versions:
- OpenSSH_8.9p1

This is likey because of a memory layout change (I havent looked into it). I will add support in the future unless there is a reason it is actually 'impossible'.

## Docker setup
I included a docker image file for conveinence.
You can also pull the docker image from Docker Hub.
```sh
docker pull wesleyjones256/ssh-keyfinder:3.0
```

## Usage

To extract SSH private keys from ssh-agent core dump with the CLI, simply run the following command:

```
Usage: python3 ./ssh-keyfinder.py <coredump file>
```

This will extract all private keys from ssh-agent and format them in OpenSSH format. The extracted keys will be displayed on the console.


Replace `<coredump>` with the path to the core dump file.


## Contribution

ssh-keyfinder is an open-source project, and contributions are welcome. If you encounter any bugs or issues, please report them on the project's [GitHub Issues](https://github.com/Kracken256/ssh-keyfinder/issues) page. If you would like to contribute code or documentation, please submit a pull request on the project's [GitHub repository](https://github.com/Kracken256/ssh-keyfinder).

## Disclaimer
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE, ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, PRIVACY, COMPLIENCE, REPUTATION, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
IN CONTRACT, STRICT LIABILITY,  OR TORT (INCLUDING NEGLIGENCE OR 
OTHERWISE) ARISING IN ANY WAY OUT  OF THE USE OF THIS SOFTWARE, 
EVEN IF ADVISED OF THE POSSIBILITY OF  SUCH DAMAGE.
