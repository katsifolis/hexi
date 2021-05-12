#!/bin/bash

rm test/dumps/*
rm test/dis/*

gcc  test/source/target.c -o    test/dumps/target
gcc  test/source/test.c -o      test/dumps/test
gcc  test/source/test1.c -o     test/dumps/test1
gcc  test/source/test2.c -o     test/dumps/test2
gcc  test/source/test3.c -o	    test/dumps/test3

python3 extractor.py
python3 binsequence.py
