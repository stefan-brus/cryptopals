#!/bin/bash

for line in $(ls source/ | grep "s[0-9]c[0-9]\.d");
do
    echo Building source/$line
    rdmd --build-only -g -unittest source/$line
done
