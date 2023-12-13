#!/bin/sh

mypy unifi-operator.py
black --skip-string-normalization -l 80 *.py
