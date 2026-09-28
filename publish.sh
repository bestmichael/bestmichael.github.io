#!/bin/zsh

git add .
git commit -m "Weitere kleine Änderungen"
git push
mkdocs gh-deploy
