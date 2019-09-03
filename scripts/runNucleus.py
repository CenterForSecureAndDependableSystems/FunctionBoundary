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

# That paper compares the results of JIM function bounddary detection with
# other tools. This script is used to run the "Nucleus" tool and obtain data
# files for that tools function boundary detection.
#
# Nucleus can be found at:
# Nucleus source code. https://www.vusec.net/projects/function-detection
#
# Documented in:
#
# D. Andriesse, A. Slowinska, and H. Bos. 2017. "Compiler-Agnostic
# Function Detection in Binaries". In 2017 IEEE European Symposium on Security
# and Privacy (EuroS&P).
#
# To run this tool, make sure "nucleus" is on your search path or modify the
# following line to include the full path
#
#


nucleusBin = 'nucleus'

import glob
import subprocess
import argparse
import os
import textwrap
    
def processFile(dirName,fileName):
    baseName=os.path.basename(fileName)
    print('Processing {:s}'.format(baseName))
    cmd=nucleusBin+' -e {:s} -d linear -f > {:s}.funcbd'.format(fileName,baseName)
    subprocess.call(cmd,shell=True)
    
def main():

   formatter = argparse.RawDescriptionHelpFormatter
   parser = argparse.ArgumentParser(formatter_class=formatter,
                                    description=textwrap.dedent('''\
Nucleus Results Interface (from JIMA toolkit). 

   This program runs nucleus and generates .funcbd files for each 
   binary in the specified directory. Results are stored in the
   current directory. Contents of these files are function start 
   address, in hex, followed by number of bytes, in decimal.
   
   Make sure that the nucleus executable is on your search path
   '''))

   required = parser.add_argument_group(title='required')
   required.add_argument('--dir', required=True,
                         help='directory of binaries')

   args = parser.parse_args()
   dirName=args.dir
   dirName=os.path.abspath(dirName)
   dirList=glob.glob(dirName+'/*')
   results=[]
   
   for fileName in sorted(dirList):
      if(os.path.isdir(dirName+'/'+fileName)): continue
      processFile(dirName,fileName)

    
if __name__ == "__main__":
   main()
