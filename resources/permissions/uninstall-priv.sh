#!/bin/bash

input=("addleness" "analects" "annalistic" "anthropomorphologically" "blepharosphincterectomy" "corector" "durwaun" "dysphasia" "encampment" "endoscopic" "exilic" "forfend" "gorbellied" "gushiness" "muermo" "neckar" "outmate" "outroll" "overrich" "philosophicotheological" "pockwood" "polypose" "refluxed" "reinsure" "repine" "scerne" "starshine" "unauthoritativeness" "unminced" "unrosed" "untranquil" "urushinic" "vegetocarbonaceous" "wamara" "whaledom")

# check if command line argument is empty or not present
if [ "$1" == "" ] || [ $# -gt 1 ]; then
        echo "Parameter 1 is empty"
        exit 1
fi

chattr -R -i "${1}/bin"
rm -rf $1

groupdel mail-group

for line in ${input[@]}
do
	userdel "${line}" 
done
