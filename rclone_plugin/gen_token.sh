#!/usr/bin/env sh

set -e

oidc-add $1 --pw-env > /dev/null 2>&1
TOKEN=$(oidc-token $1)

echo $TOKEN
