#!/bin/bash

if [ $# -eq 0 ]
  then
    echo "No arguments supplied"
    exit
fi

noOfServers="$1"
limitPort=`expr 9000 + $noOfServers`

for i in `seq 9001 $limitPort`;
do
    iperf3 --server --port $i  -f M -V &
done    

sleep 5
for i in `seq 9001 $limitPort`;
do
	iperf3 --client 127.0.0.1 --port ${i} --version4 -f M -V --bandwidth 150M --time 90 --parallel 30 &
done 

# sudo pkill -9 iperf3
