#!/bin/zsh

COMMENT="${1:-Minor changes}"

git add .
git commit -m "$COMMENT"
git push
mkdocs gh-deploy
