#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  test.py
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

import os, errno

def main(args):
    filename = "decrypted.txt"
    directory_name = "DecryptedFiles"
    
    if not os.path.exists(os.path.dirname(directory_name)):
        try:
            os.makedirs(directory_name)
        except OSError as exc:
            if exc.errno != errno.EEXIST:
                raise
    os.chdir(directory_name)
    f = open(filename,'wb')
    f.seek(0,2)
    f.write("test file name\n")
    print(os.getcwd())
    #for i in range (0,100):
        
    
if __name__ == '__main__':
    import sys
    sys.exit(main(sys.argv))
