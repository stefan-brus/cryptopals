#!/bin/bash

for line in $(ls source/ | grep "s[0-9]c[0-9]\.d");
do
    echo Running source/$line
    rdmd -g -unittest source/$line
done
