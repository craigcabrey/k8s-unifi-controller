#!/bin/sh

REPO_ROOT=$(git rev-parse --show-toplevel)

pip install -r "${REPO_ROOT}/requirements.txt"
pip install urllib3~=2.0

pip install -r "${REPO_ROOT}/test-requirements.txt"

mypy --install-types --non-interactive
