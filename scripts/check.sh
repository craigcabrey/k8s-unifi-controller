#!/bin/sh

REPO_ROOT=$(git rev-parse --show-toplevel)

mypy "${REPO_ROOT}/controller.py"
black --skip-string-normalization -l 80 "${REPO_ROOT}"/*.py
