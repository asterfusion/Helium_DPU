#!/bin/sh

# Run filter-branch to remove proprietary files
git filter-branch --force --index-filter '\
git rm -rf --cached --ignore-unmatch drivers/net/mvgiu \
git rm -rf --cached --ignore-unmatch devtools/mv-filter-branch.sh \
' --prune-empty @ b496cc79b..HEAD

