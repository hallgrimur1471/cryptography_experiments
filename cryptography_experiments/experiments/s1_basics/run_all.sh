#!/usr/bin/env bash

dir=`dirname $0`
cd $dir
echo `pwd`
programs=( `find . -name 'c*.py' | sort | sed 's/\n/ /g'` )
for program in "${programs[@]}"
do
    echo "******************************************************"
    echo "*** RUNNING ${program}"
    echo "******************************************************"
    $program
    if [ $? -eq 1 ]; then
        #echo "Failure at: ${program}."
        echo "Stop."
        exit 1
    else
        echo "Success."
    fi
done
