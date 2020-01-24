#!/bin/bash

IP=$1

nmap_aggr="nmap -A -T4 -p- -Pn -v $IP"
nmap_reg="nmap -p- -T4 -Pn -v $IP"

# add conditional to choose which scan type, set aggresive to default.

# if aggresive
if [[ ! -d "autoenum" ]];then mkdir autoenum; fi
if [[ ! -d "autoenum/aggr_scan/raw" ]];then mkdir -p autoenum/aggr_scan/raw; fi
if [[ ! -d "autoenum/aggr_scan/ports_and_services" ]];then  mkdir -p autoenum/aggr_scan/ports_and_services; fi
if [[ ! -d "autoenum/aggr_scan/exploits" ]];then mkdir -p autoenum/aggr_scan/exploits; fi
$nmap_aggr | tee -a autoenum/aggr_scan/raw/first_pass
cat autoenum/aggr_scan/raw/first_pass | grep -i "discovered" >> autoenum/aggr_scan/ports_and_services/ports_discovered
cat autoenum/aggr_scan/raw/first_pass | grep "open" | awk -F 'Discovered' '{print $1}' | sed '/^$/d' >> autoenum/aggr_scan/ports_and_services/services_running
cat autoenum/aggr_scan/raw/first_pass | grep 'OS' | sed '1d' | sed '$d' | cut -d '|' -f 1 | sed '/^$/d' >> autoenum/aggr_scan/ports_and_services/OS_detection
cat autoenum/aggr_scan/raw/first_pass | grep "script results" > autoenum/aggr_scan/ports_and_services/script_output; cat autoenum/aggr_scan/raw/first_pass | grep "|" | sed '$d' >>  autoenum/aggr_scan/ports_and_services/script_output

# run nmap xml output thru searchsploit as a 'first sweep' and then run services names
$nmap_aggr -oX autoenum/aggr_scan/raw/nmap_out.xml
searchsploit -v --nmap -w autoenum/aggr_scan/raw/nmap_out.xml | tee -a autoenum/aggr_scan/exploits/searchsploit_nmap


#############################################################################################################################
#for service in $(cat services); do searchsploit $service | tee -a searchsploit_$service # create method to remove files if no exploits are found


# IDEAS
# grep out services and grep out services and their version #, pass that to searchsploit
# basically pull services on open ports and enum further
# neatly organize output
# searchsploit -w returns websites instead of paths, maybe could list the exploits returned and point them to site containing exploit
# mirror exploit maybe?
