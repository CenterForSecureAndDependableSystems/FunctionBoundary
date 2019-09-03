#!/usr/bin/env python3
#
#   This file is part of the JIMA Binary Analysis Toolkit, built and
#   distributed by the University of Idaho's Center for Secure and
#   Dependable Systems.  http://www.csds.uidaho.edu
#
#   Full source is available at CSDS github:
#
#   https://github.com/CenterForSecureAndDependableSystems/JIMA
#
#   JIMA is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   JIMA is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with JIMA.  If not, see <https://www.gnu.org/licenses/>.
#
#   Please include modification history here (most recent first):
#
#   Date (DD/MM/YYYY)   Author:            Comments
#
#   19/06/2018          Jim Alves-Foss     First instance of GPL version 
#

# One part of the evaluation of JIMA invovles the detection of function
# boundaries. The results of that evaluation are published in
#
# J. Alves-Foss and J. Song. 2019. "Function Boundary Detection in Stripped
# Binaries" in Annual Computer Security Applications Conference (ACSAC).

#N That paper compares the results of JIM function bounddary detection with
# other tools. This script is used to run the "Ghidra" tool and obtain data
# files for that tools function boundary detection.
#
# Ghidra can be found at:
# NSA Ghidra tool https://www.nsa.gov/resources/everyone/ghidra/
#
# To run this tool, make sure the ghdira support directort is on your
# search path or modify the following line to include the full path
#

ghidraSupportDir = '/home/jimaf/public/ghidra/support'


ghidraBin = 'analyzeHeadless'
ghidra = ghidraSupportDir + '/'+ghidraBin

import glob
import subprocess
import argparse
import os
import sys
import io
import textwrap


def mkdir(fileName):
    if( not os.path.exists(fileName)):
        subprocess.call(['mkdir','-p',fileName])

def processFile(dirName,fileName):
    baseName=os.path.basename(fileName)
    print('Processing {:s}'.format(baseName))

    cmd='objdump -f '+fileName

    p1 = subprocess.check_output(cmd,shell=True)

    dynamic=False
    inFile = io.BytesIO(p1)
    for line in inFile:
        line=str(line)
        if line.find('DYNAMIC')>0:
            dynamic=True
            print('DYNAMIC')
            break

    mkdir('testLab')
    cmd=ghidra+' testLab testProj -postScript FunctionBoundaryList.java -import {:s} -deleteProject'.format(fileName)    
    if dynamic:
        cmd+=' -loader ElfLoader -loader-imagebase 0'
    subprocess.call(cmd,shell=True)
    


def main():
   global opSet
   formatter = argparse.RawDescriptionHelpFormatter
   parser = argparse.ArgumentParser(formatter_class=formatter,
                                    description=textwrap.dedent('''\
Ghidra Results Interface (from JIMA toolkit). 

   This program runs the Ghidra headless analyzer, generates .jimagt files
   for each binary in the specified directory. Results are stored in the
   current directory. Contents of these files are function start 
   address, in hex, followed by number of bytes, in decimal.
   
   Make sure that the ghidra support directory is on your search path
   '''))

   required = parser.add_argument_group(title='required')
   required.add_argument('--dir', required=True, type=str,
                         help='directory of binaries')

   args = parser.parse_args()
   dirName=args.dir
   dirName=os.path.abspath(dirName)
   dirList=glob.glob(dirName+'/*')
   results=[]
   
   for fileName in sorted(dirList):
      if(os.path.isdir(dirName+'/'+fileName)): continue
      if(os.path.isdir(fileName)): continue      
      processFile(dirName,fileName)

      
    
if __name__ == "__main__":
   main()
