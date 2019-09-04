# FunctionBoundary
Dataset and Scripts for Function Boundary Detection -- See ACSAC Publication
Jim Alves-Foss and Jia Song, "Function Boundary Detection in Stripped Binaries",
ACSAC'19, 2019. https://doi.org/10.1145/3359789.3359825

Directories:

<ul>
<li>  script contains executable scripts used to generate function boundaries for three tools: JIMA, nucleus and Ghidra; and a tool to countup the results. Also contains our JIM executable -- called "processJil".
<li>  ghidra_scripts contains the java file that Ghidra executes to calcalate the function boundaries. The file needs to be placed in your Ghidra scripts directory.
  <li> dataset contains most of the data sets we used in the paper. We had to remove the files greater than 100MB, which
    includes some of the files generated by SPEC and also Chrome.
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


NOTE: To run nucleus, you will have to download and install it. Make sure the executable is on your path. 
- https://www.vusec.net/projects/functrion-detection


NOTE: To run ghidra, you will have to download and install it. Make sure the executable is on your path. 
- https://www.nsa.gov/resources/everyone/ghidra
You will have to place the "ghidra_scripts" file in the appropriate directory for your installation of Ghidra.
