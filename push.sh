#!/bin/bash

cp /usr/bin/autoenum.sh autoenum.sh

git add .
git commit -m "autoenum.sh"
git push origin master >> justcheckit

if grep -q "[rejected]" "justcheckit";then
	git pull
	git add .
	git commit -m "autoenum.sh"
	git push origin master
fi
