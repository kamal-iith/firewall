#!/bin/bash

if [ $# -eq 0 ]
  then
    echo "No arguments supplied"
    exit
fi

echo "{\"rules\": [" > database.json

noOfServers=$1
limitPort=`expr 9000 + $noOfServers`

for i in `seq 9001 $limitPort`;
do
	echo "{\"sourceip\": \"any\", \"action\": \"ACCEPT\", \"protocol\": \"all\", \"dport2\": $i, \"sport1\": null, \"sport2\": null, \"dport1\": $i}," >> database.json
done

truncate -s-2 database.json
echo -e "\n]}" >> database.json