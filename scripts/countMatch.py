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

# This file contains functions needed to tally function recognition
# success
#
# Separate documentation exists for the JIL file format.
#

import glob
import subprocess
import argparse
import os
import textwrap
import csv
import sys


def myint(intStr):
    strIn = intStr
    if isinstance(intStr,int): return intStr
    if (intStr.startswith('$')):
        intStr = intStr[1:]
    if(intStr.startswith('0x')):
        result=int(intStr[2:],16)
    elif(intStr.startswith('-0x')):
        result=-int(intStr[3:],16)
    else:
        result=int(intStr)

    return result

categories=['fpSt','fpBd','tpSt','tpBd','longBd','shortBd','missing','gt','precSt','recallSt','f1St','precBd','recallBd','f1Bd']

def _main():

   formatter = argparse.RawDescriptionHelpFormatter
   parser = argparse.ArgumentParser(formatter_class=formatter,
                                    description=textwrap.dedent('''\
Function Boundary Counter (from JIMA toolkit). 

   This program reviews the tool-generated function boundaries against
   the "ground truth" generated from unstripped binaries. The results
   are stored in a  .res file for each file -- detailing the resutls, 
   and summarized in two csv files: results.csv and results1.csv.
   
   '''))

   required = parser.add_argument_group(title='required')
   required.add_argument('--funcDir', required=True, 
                         help='directory of function boundary files')

   required.add_argument('--symDir', required=True, 
                         help='directory of ground truth symbols')   

   args = parser.parse_args()
   dirName=args.funcDir
   dirName=os.path.abspath(dirName)

   symdirName=args.symDir
   symdirName=os.path.abspath(symdirName)

   suffix='newgt'
   dirList=glob.glob('*.'+suffix)
   if(len(dirList)==0):
      suffix='funcbd'
      dirList=glob.glob('*.'+suffix)
   if(len(dirList)==0):
      suffix='bap*gt'
      dirList=glob.glob('*.'+suffix)
   myGt={}
   sym={}
   res={}
   matches=0
   longs=0
   shorts=0
   gts=0
   others=0
   missings=0
   fileIds=[]

   for cat in categories:
      res[cat]={}

   for file in dirList:
      fId=os.path.basename(file)
        
      fileIds.append(fId)
      myGt={}
      sym={}
      buried={}
      numBuried=0
      
      len1=file.rfind('.')
      symFile=file[:len1]+'.sym'
      lastAddr=0
      with open(file,'r') as f:
         cnt=0
         for line in f:
            cnt+=1
            words=line.split()
            if(len(words)<2):
               print('{!s}:: line {:d} is {!s}'.format(file,cnt,line))
               continue
            addr=int(words[0],16)
            myGt[addr]=myint(words[1])

                
      with open(symdirName+'/'+symFile,'r') as f:

         try:
            line = f.readline()
            words=line.split()
            if (words[0]=='text'):
               start = int(words[1],16)
               endByte=int(words[2],16)
            else:
               start=0
               endByte=0
               sym[myint(words[0])]=myint(words[1])                
            for line in f:
               words=line.split()
               if(len(words)<2):
                  print('Sym Line {:d} is {:s}'.format(line))
                  sys.exit(-1)                
               sym[myint(words[0])]=myint(words[1])
         except:
            print('Error for {:s} from {:s}'.format(symFile,file))
            sys.exit(-1)

      if(start==0):
         symKeys=sorted(sym.keys())
         start = symKeys[0]
         endByte=symKeys[-1]+sym[symKeys[-1]]-1


            
      for cat in categories:
         res[cat][fId]=0

      cnt=0
      cnt2=0
      cnt4=0
      aligned=1
      for x in sym:
         cnt+=1
         if (x % 16) == 0:cnt4+=1
         elif (x%2)==0: cnt2+=1

      if(cnt4/cnt > .9):
         aligned=4
      elif(cnt2/cnt >.9):
         aligned=2
      else:
         print('No align -- really')
        
      match={}
      short={}  
      shortLen={}
      longGuess={}
      longLen={}
      missing={}
      other={}

        
      for addr in myGt:
         if(addr<start or addr>endByte):
            continue
         if addr not in sym:
            res['fpSt'][fId]+=1
            res['fpBd'][fId]+=1
            other[addr]=myGt[addr]
            continue
         res['tpSt'][fId]+=1
         if(sym[addr]==0 or myGt[addr]==sym[addr]):
            res['tpBd'][fId]+=1
            match[addr]=myGt[addr]
         elif(myGt[addr]>sym[addr]):
            res['longBd'][fId]+=1
            res['fpBd'][fId]+=1                
            longGuess[addr]=myGt[addr]
            buried[addr]=[]
            longLen[addr]=longGuess[addr]-sym[addr]

                
         else:
            if(aligned==4 and
               sym[addr]-myGt[addr] < 16):
               res['tpBd'][fId]+=1
               match[addr]=myGt[addr]
            elif(aligned==2 and
                 sym[addr]+1 == myGt[addr]):
               res['tpBd'][fId]+=1
               match[addr]=myGt[addr]
            elif(myGt[addr]+1==sym[addr]):
               res['tpBd'][fId]+=1
               match[addr]=myGt[addr]
            else:
               res['shortBd'][fId]+=1
               res['fpBd'][fId]+=1                    
               short[addr]=myGt[addr]
               shortLen[addr]=short[addr]-sym[addr]

      for addr in sym:
         res['gt'][fId]+=1
         if addr not in myGt:
            res['missing'][fId]+=1
            missing[addr]=sym[addr]
            for longAddr in longGuess:
               if(addr > longAddr
                  and addr < longAddr + longGuess[longAddr]):
                  buried[longAddr].append(addr)
                  numBuried+=1
                
      if(res['tpSt'][fId]==0):
         res['precSt'][fId]=0
      else:
         res['precSt'][fId]=res['tpSt'][fId]/(res['tpSt'][fId]+res['fpSt'][fId])
      if(res['tpBd'][fId]==0):
         res['precBd'][fId]=0
      else:
         res['precBd'][fId]=res['tpBd'][fId]/(res['tpBd'][fId]+res['fpBd'][fId])
        
      res['recallSt'][fId]=res['tpSt'][fId]/res['gt'][fId]
      res['recallBd'][fId]=res['tpBd'][fId]/res['gt'][fId]        
      
      if(res['precSt'][fId]==0):
         res['f1St'][fId]=0
      else:
         res['f1St'][fId]=2*res['precSt'][fId]*res['recallSt'][fId]/(res['precSt'][fId]+res['recallSt'][fId])

      if(res['precBd'][fId]==0):
         res['f1Bd'][fId]=0
      else:
         res['f1Bd'][fId]=2*res['precBd'][fId]*res['recallBd'][fId]/(res['precBd'][fId]+res['recallBd'][fId])

      len1=file.rfind('.')
      resFile=file[:len1]+'.res'
        
      with open(resFile,'w') as resFn:
         resFn.write('{:d}({:5.2%}) matches out of {:d} functions with {:d} others {:d} missing\n'.format(len(match),len(match)/len(sym),len(sym),len(other),len(missing)))
         resFn.write('{:d} long and {:d} short and {:d} buried\n'.format(len(longGuess),len(short),numBuried))
         resFn.write('\nShort {:d} ({:5.2%})\n'.format(len(short),len(short)/len(sym)))
         for x in sorted(short.keys()):
            resFn.write('0x{:x} {:5d}  ({:5d} end at 0x{:x}\n'.format(x,short[x],shortLen[x],x+short[x]-1))

         resFn.write('\nLong {:d} ({:5.2%})\n'.format(len(longGuess),len(longGuess)/len(sym)))
         for x in sorted(longGuess.keys()):
            resFn.write('0x{:08x} {:5d}  ({:5d} end at 0x{:08x} -- buried {:d})\n  '.format(x,longGuess[x],longLen[x],x+longGuess[x]-1,len(buried[x])))

            cnt=0
            for bury in sorted(buried[x]):
               resFn.write('0x{:08x}  '.format(bury))
               cnt+=1
               if (cnt%5 ==0): resFn.write('\n  ')
            if(cnt >0):
               resFn.write('\n')
            resFn.write('\n')            
            
            

         resFn.write('\nOther {:d} ({:5.2%})\n'.format(len(other),len(other)/len(sym)))
         for x in sorted(other.keys()):
            resFn.write('0x{:x} {:5d}\n'.format(x,other[x]))

         resFn.write('\nMissing {:d} ({:5.2%})\n'.format(len(missing),len(missing)/len(sym)))
         for x in sorted(missing.keys()):
            resFn.write('0x{:x} {:5d}\n'.format(x,missing[x]))

      matches +=len(match)
      shorts +=len(short)
      longs +=len(longGuess)
      gts+=len(sym)
      others+=len(other)
      missings+=len(missing)

   with open('results.csv','w') as f:
      str='name,'
      for cat in categories:
         str+=cat+','
      str=str[:-1]
      f.write(str+'\n')

      for fId in sorted(fileIds):
         str=fId+','
         for cat in categories:
            if(cat.startswith('prec') or
               cat.startswith('recall') or
               cat.startswith('f1')):
                  str+='{:5.2%},'.format(res[cat][fId])
            else:
               try:
                  str+='{:d},'.format(res[cat][fId])
               except:
                  print('String is {:s} for cat {:s} and fId = {:s}'.format(str,cat,fId))
                  sys.exit(-1)
         str=str[:-1]
         f.write(str+'\n')

            
   with open('results1.csv','w') as f:
      sKeys=sorted(short.keys())
      lKeys=sorted(longGuess.keys())
      mKeys=sorted(missing.keys())
      maxShort=len(sKeys)
      maxLong=len(lKeys)
      maxMissing=len(mKeys)
      
      maxCnt=max(maxShort,max(maxLong,maxMissing))
      f.write('short,long,missing\n')

      for i in range(maxCnt):
         if i<maxShort:
            f.write('0x{:x},'.format(sKeys[i]))
         else:
            f.write('0x0,')
         if i<maxLong:
            f.write('0x{:x},'.format(lKeys[i]))
         else:
            f.write('0x0,')
         if i<maxMissing:
            f.write('0x{:x}\n'.format(mKeys[i]))
         else:
            f.write('0x0\n')                

   print('Found {:d} total matches in {:d} files from {:d} gts for {:5.2%}'.format(matches,len(fileIds),gts,matches/gts))            
   print('Found {:d} shorts ({:7.4%}), {:d} longs ({:7.4%}) {:d} ({:7.4%}) other and {:d} ({:7.4%}) missing'.format(shorts,shorts/gts,longs,longs/gts,others,others/gts,missings,missings/gts))

   precision=(matches+longs+shorts)/(matches+longs+shorts+others)
   recall = (matches+longs+shorts)/gts
   f1 = 2*precision*recall/(precision+recall)
   print('\nFor starts: Precision {:5.2%} and recall {:5.2%} and F1= {:5.2%}'.format(precision,recall,f1))

   precision=(matches+shorts)/(matches+longs+shorts+others)
   recall=(matches+shorts)/gts
   f1 = 2*precision*recall/(precision+recall)    
   print('\nFor boundary and shorts {:d}: Precision {:5.2%} and recall {:5.2%} and F1= {:5.2%}'.format(shorts,precision,recall,f1))    

   precision = matches/(matches+longs+shorts+others)
   recall = matches/gts
   f1 = 2*precision*recall/(precision+recall)        
   print('\nFor boundary: Precision {:5.2%} and recall {:5.2%} and F1= {:5.2%}\n'.format(precision,recall,f1))

   fileStatsLabels=['longBd','shortBd','fpSt','missing','gt']

   from collections import OrderedDict
   for statType in fileStatsLabels:
      if(statType == 'gt'): continue
      dd=OrderedDict(sorted(res[statType].items(), key = lambda x: x[1]))
      
      cnt =0 
      for dId in reversed(dd):
         if(dd[dId]==0): cnt+=1
            
      print('Top {:s} is {:d} perfect out of {:d}  = {:5.2%}'.format(statType,cnt,len(dd),cnt/len(dd)))

      cnt=1
      for dId in reversed(dd):
         print('{:3d}: {:5d} ({:6.2%}) : {:s}'.format(cnt,dd[dId],dd[dId]/res['gt'][dId],dId))
         cnt += 1
         if(cnt>5): break

      print(' ')


   for statType in ['f1St']:
      dd=OrderedDict(sorted(res[statType].items(), key = lambda x: x[1]))

      cnt =0 
      for dId in dd:
         if(dd[dId]==1): cnt+=1
            
      print('Bottom {:s} is {:d} perfect out of {:d}  = {:5.2%}'.format(statType,cnt,len(dd),cnt/len(dd)))

      cnt=1
      for dId in dd:
         print('{:3d}: {:5.2%} : {:s}'.format(cnt,dd[dId],dId))
         cnt += 1
         if(cnt>15): break

      print(' ')        
        
    
if __name__ == "__main__":
    _main()
