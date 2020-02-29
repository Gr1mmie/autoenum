#!/bin/bash

# clean out nasty output

domain="$1"
wget -O index $domain

cat index | grep -o "[^/]*\.$domain" | sort -u | tee -a lvl1_subs

switch="true"
while $switch && [[ -f "lvl1_subs" ]];do
	file="lvl1_subs"
#	i=1
	for sub in $(cat $file);do
		wget -O subdomains $sub; cat subdomains | grep -o "[^/]*\.$domain" | tee -a  multi_lvl
	done
	switch="false"
done
touch subs
mv lvl1_subs subs
mv multi_lvl subs
rm index subdomains

