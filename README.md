# FunctionBoundary
Dataset and Scripts for Function Boundary Detection -- See ACSAC Publication
Jim Alves-Foss and Jia Song, "Function Boundary Detection in Stripped Binaries",
ACSACX'19, 2019. https://doi.org/10.1145/3359789.3359825

Directories:

<ul>
<li>  script contains executable scripts used to generate function boundaries for three tools: JIMA, nucleus and Ghidra; and a tool to countup the results. Also contains our JIM executable -- called "processJil".
<li>  ghidra_scripts contains the java file that Ghidra executes to calcalate the function boundaries. The file needs to be placed in your Ghidra scripts directory.
  <li> contains the data sets we used in the paper.
  </ul>
    
Example:
```
mkdir tmpJIMA
cd tmpJIMA
../scripts/runJima --dir ../datasets/strippedTestSuites/x64gcc
../scripts/countMatch.py --binDir ./ --symDir ../datasets/groundTruth/x64gcc
```

This will create the data files from the JIMA tool, .res files for each file with details 
and .csv files with combined results
