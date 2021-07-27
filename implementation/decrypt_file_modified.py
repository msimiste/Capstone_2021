#!/usr/bin/env python
import struct, sys, os
import argparse
from collections import namedtuple
from Crypto.Cipher import AES
from Crypto.Cipher import DES3
import magic

def decrypt_file(filename, key_val, mode=AES.MODE_CBC, iv='\x00'*16, trim=None):
    """Attempt decryption of a file.

    Args:
        filename: The name of the file you want to decrypt
        key_val: The key you want to use to decrypt with
        mode: The cipher block mode you want to decrypt with
        iv: The IV you want to use to decrypt with
        trim: The amount to trim to the file by before decrypting

    Returns:
        The decrypted data.

    Raises:
        Something if decryption failed.
    """
    with open(filename, 'rb') as f:
        encrypted_data = f.read()

    if trim:
        encrypted_data = encrypted_data[trim:]

    try:
        #print("Line 107 {} {}".format(len(key_val),key_val))
        #print("EncryptedData Mod 16: {} ".format(len(encrypted_data)%16))      
        cipher = AES.new(key_val, mode=mode, IV=iv)
        decrypted_data = cipher.decrypt(encrypted_data)
        #print(len(decrypted_data))
        #decrypted_data = decrypted_data[:-ord(decrypted_data[-1])] # Unpad the data
    except Exception as e:
        print("Line 111 {} {} {}".format(e,len(key_val),key_val))
        decrypted_data = ""

    return decrypted_data

def file_is_decrypted(filedata):
    """Check if a file is a common file type, aka successfully decrypted.

    Args:
        filedata: The data of the file to check.

    Returns:
        True if file is a common file type, False otherwise.
    """

    type_ = magic.from_buffer(filedata)
    common_types = ('ASCII', 'JPEG', 'DOC', 'GIF', 'MSVC', 'C source', 'PNG', 'Unicode text','PDF')
    if any(filetype in type_ for filetype in common_types):
        return True
    else:
        return False

def main(key_blob):
    """Decrypt ransomed file.

    Args:
        key_blob: An encryption key.

    Returns:
        True if successfully decrypted a file, False otherwise.
    """
   
    key_val = key_blob.decode('hex')
    print(key_val.encode('hex'))
    decrypted_data = decrypt_file(args.file, key_val, args.mode, args.iv,args.trim)
    isDecrypted = file_is_decrypted(decrypted_data)
    print(isDecrypted)
    if(isDecrypted):
        print("File {}, key = {}, iv = {}, mode = {}, loc = {}".format(args.file, key_val.encode('hex'), args.iv.encode('hex'), args.mode,args.out.name))
        args.out.write(decrypted_data)
        sys.exit(0)
        return True
    return False   

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', required=True,
        help="Required. Specify the encrypted file to decrypt.")
    parser.add_argument('-k', '--key_blobs', required=False, default='keys.txt',
        help="Specify where the list of potential keys is, default=keys.txt")
    parser.add_argument('-k0', '--key_blob', required=False,
        help="Specify a single key to use.")
    parser.add_argument('-o', '--out', default=sys.stdout,
        help="Specify where you want the decrypted file to go, default=stdout")
    parser.add_argument('-m', '--mode', default='cbc', choices=['cbc', 'ofb', 'ecb'],
        help="Specify what mode was used for encryption, default=cbc")
    parser.add_argument('-v','--iv', default='\x00'*16,
        help="Specify what IV was used for encryption, default=0x00*16")
    parser.add_argument('-x', '--exhaustive', action='store_true', default=False,
        help="Continue attempting decryption, even after successfully finding a common file type.")
    parser.add_argument('-t','--trim',type=int, default=1024,
        help="Amount to attempt trimming up to, default=1024")

    args = parser.parse_args()

    if (not args.key_blobs and not args.key_blob):
        print("You must provide either a --key_blob xor --key_blobs")
        sys.exit(3)

    if args.mode == 'cbc':
        args.mode = AES.MODE_CBC
    elif args.mode == 'ofb':
        args.mode = AES.MODE_OFB
    elif args.mode == 'ecb':
        args.mode = AES.MODE_ECB
    else:
        print("Improper block cipher mode specified")
        sys.exit(2)

    orig_file_name = None
    if args.out != sys.stdout:
        orig_file_name = args.out
        out = open(args.out, 'wb')
        args.out = out

    if args.key_blob:
        key_blobs = [args.key_blob]
    else:
        key_blobs = set([line.rstrip('\r\n') for line in open(args.key_blobs)])
    
    count = 1
    for key_blob in key_blobs:
        if main(key_blob):
            if args.exhaustive:
                # Keep going...
                count += 1
                if orig_file_name is not None:
                    # Obtain the next file name, to not overwrite all the results
                    next_filename = orig_file_name + str(count)
                    args.out.close()
                    args.out = open(next_filename, 'wb')
            else:
                # We're done!
                sys.exit(0)
