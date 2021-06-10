#!/bin/bash

cd test/
rm -rf dumps/*
rm -rf dis/*
make
cd dumps/
rm -rf obj/
cd ../../

python3 binsequence/binsequence.py
