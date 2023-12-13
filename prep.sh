#!/bin/sh

mypy controller.py
black --skip-string-normalization -l 80 *.py
