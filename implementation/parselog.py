#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  parselog.py
#  
#  Copyright 2021 simdevs <simdevs@simdevs>
#  
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#  
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#  
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#  
#  

import struct, os,gc,time, errno
import decrypt_file_modified as df

def removePadding(data):
    end = len(data)-1
    while(b'\x00' in data[end]):
        end = end-1
    data = data[:end+1]
    return data
    
def parseLog(filename):
    f = open(filename,'rb')
    lines = f.readlines()
    count = 0
    
    
    try:   
        for line in lines:
            t = line.split('=')
            if(len(t)==3):# and (count < 5):
                filepath = t[1].strip()
                start = filepath.index('C:')
                finish = filepath.index('\t\t')
                filepath = filepath[start:finish]
                tailstart = filepath.rfind('\\')+1
                tailend = filepath.index('.WNCRY')+6
                tail = filepath[tailstart:tailend]
                fExtension = tail.split('.')[1]
                outfile = filepath[:tailstart] + tail[:tail.index('.WNCRY')]
                key = t[2].strip()
                key_val = key.decode('hex')
                decrypted_data = df.decrypt_file(filepath[:tailend],key_val,2,'\x00'*16,280)
                isDecrypted = df.file_is_decrypted(decrypted_data)
                if(isDecrypted):
                    decrypted_data = removePadding(decrypted_data)
                    #print(tail,filepath,fExtension,key)
                    print(outfile)
                    manifest = open('manifest.txt','a')                
                    manifest.write(outfile + ' ' + key + '\n')                
                    manifest.close()
                    fout = open(outfile,'wb')
                    fout.write(decrypted_data)
                    fout.close()
                    fileOnly = tail[:tail.index('.WNCRY')]
                    fout1 = open(fileOnly,'wb')
                    fout1.write(decrypted_data)
                    fout1.close()
                    filepath = filepath[:len(filepath)-1]
                    os.remove(filepath)
                else:                    
                    failed = open('FailedDecryption.txt','a')
                    failed.write(filepath + ' ' + key + '\n')
                    failed.close()
            else:                
                failed = open('FailedDecryption.txt','a')
                failed.write(filepath + ' ' + key + '\n')
                failed.close()
            del lines[lines.index(line)]
            gc.collect()
            time.sleep(0.5)
    except Exception as e:
        gc.collect()
        f2 = open(filename,'wb')
        for line in lines:
            f2.write(line)
        f.close()
        f2.close()
        print(e)
        sys.exit(0)
   
    f2 = open(filename,'wb')
    for line in lines:
        f2.write(line)
    f.close()
    f2.close()
        
    
    
def main(args):
    filename = args[1]
    
    f = open(filename,'rb')
    length = len(f.readlines())
    f.close()
    directory_name = "DecryptedFiles"
    
    if not os.path.exists(os.path.dirname(directory_name)):
        try:
            os.makedirs(directory_name)
        except OSError as exc:
            if exc.errno != errno.EEXIST:
                raise
    os.chdir(directory_name)                    
    parseLog(filename)
       
            

if __name__ == '__main__':
    import sys
    sys.exit(main(sys.argv))
