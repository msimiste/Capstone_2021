#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  cleanSystem.py
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

import struct,os,_winreg, shutil

tasks = ['tasksche.exe','taskhsvc.exe','mssecsvc.exe','@WanaDecryptor@.exe']

def stopservice():
    os.system("sc stop mssecsvc2.0")
    os.system("sc config mssecsvc2.0 start= disabled")
    
def killtasks():
    data = os.popen('tasklist').readlines()
    for task in tasks:
        for line in data:
            if task in line:
                print('{} in {}'.format(task,data.index(line)))
                os.system("taskkill /F /IM {} /T".format(task))
                
                
def removeRegKeys():
    root = _winreg.ConnectRegistry(None,_winreg.HKEY_LOCAL_MACHINE)
    wcryKey = _winreg.OpenKeyEx(root,r"Software\Wanacrypt0r")
    randompath, type_ = _winreg.QueryValueEx(wcryKey,"wd")
    randomfolder = randompath.split('\\')[2]
    #autorunKey = _winreg.OpenKeyEx(root,r"Software\Microsoft\Windows\CurrentVersion\Run")
    
    try:
        os.system("reg delete {} /v {} /f".format("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",randomfolder))
        os.system("reg delete {} /v {} /f".format("HKEY_LOCAL_MACHINE\SOFTWARE\WanaCrypt0r","wd"))
        os.system("reg delete {} /v {} /f".format("HKEY_LOCAL_MACHINE\SOFTWARE","WanaCrypt0r"))
        shutil.rmtree(randompath)
    except WindowsError as e:
        print("Error Deleting Key {}".format(e))
    else:
        print("Success, keys deleted")

def main(args):
    stopservice()
    killtasks()
    removeRegKeys()

if __name__ == '__main__':
    import sys
    sys.exit(main(sys.argv))
