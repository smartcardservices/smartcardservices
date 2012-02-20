#!/bin/bash

Version_Major=`grep -m 1 CRYPTOKIVERSION_LIBRARY_MAJOR ./version.hpp |cut -d" " -f3`
Version_Minor=`grep -m 1 CRYPTOKIVERSION_LIBRARY_MINOR ./version.hpp |cut -d" " -f3`
Version_Minor2=`grep -m 1 CRYPTOKIVERSION_LIBRARY_MINOR2 ./version.hpp |cut -d" " -f3`
Version_Minor3=`grep -m 1 CRYPTOKIVERSION_LIBRARY_MINOR3 ./version.hpp |cut -d" " -f3`
echo $Version_Major\.$Version_Minor\.$Version_Minor2\.$Version_Minor3
