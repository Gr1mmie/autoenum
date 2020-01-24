#!/bin/bash

IP=$1

nmap_aggr=$(nmap -A -T4 -p- -Pn -v $IP)
nmap_reg=$(nmap -p- -T4 -Pn -v $IP)

# add conditional to choose which scan type, set aggresive to default.

# if aggresive
if [[ ! -d "autoenum" ]];then mkdir autoenum; fi
if [[ ! -d "autoenum/aggr_scan" ]];then mkdir -p autoenum/aggr_scan; fi
if [[ ! -d "autoenum/aggr_scan/ports_and_services" ]];then  mkdir autoenum/aggr_scan/ports_and_services; fi
if [[ ! -d "autoenum/aggr_scan/exploits" ]];then mkdir autoenum/exploits; fi
$nmap_aggr | tee -a autoenum/aggr_scan/raw
cat autoenum/aggr_scan/raw | grep -i "discovered" | tee -a autoenum/aggr_scan/ports_and_services/ports_discovered
cat autoenum/aggr_scan/raw | grep "open" | awk -F 'Discovered' '{print $1}' | sed '/^$/d' | tee -a autoenum/aggr_scan/ports_and_services/services_running
cat autoenum/aggr_scan/raw | grep 'OS' | sed '1d' | sed '$d' | cut -d '|' -f 1 | sed '/^$/d' | tee -a autoenum/aggr_scan/ports_and_services/OS_detection
cat autoenum/aggr_scan/raw | grep "script results" | tee autoenum/aggr_scan/ports_and_services/script_output; cat autoenum/aggr_scan/raw | grep "|" | sed '$d' | tee -a autoenum/aggr_scan/ports_and services/script_output

#first things first, update searchsploit
#searchsploit -u
# run nmap xml output thru searchsploit as a 'first sweep' and then run services names
$nmap_aggr -oX autoenum/raw_scan/out
searchsploit -v --nmap -w autoenum/raw_scan/out | tee -a autoenum/exploits/searchsploit_firstpass


# if reg
#$nmap_reg $IP | tee -a reg_scan
#cat reg_scan | grep -i "discovered" | tee -a ports_discovered

###########################################################################################################################################################################
#for service in $(cat services); do searchsploit $service | tee -a searchsploit_$service # create method to remove files if no exploits are found


# IDEAS
# grep out services and grep out services and their version #, pass that to searchsploit
# basically pull services on open ports and enum further
# neatly organize output
# searchsploit -w returns websites instead of paths, maybe could list the exploits returned and point them to site containing exploit
# mirror exploit maybe?
