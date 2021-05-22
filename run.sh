#!/bin/bash

cd test/
rm -rf dumps/*
rm -rf dis/*
make
cd dumps/
rm -rf obj/
cd ../../

pypy3 extractor.py
