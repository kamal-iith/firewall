# CS6909 Network Security, Assignment 4: Firewall using raw sockets
Created By:
* Anurag Reddy Karri, MA18BTECH11001
* Abhignya Pampati, MA18BTECH11005
* Dheekshitha Bheemanath, CS18BTECH1006
* Havya Karuturi, CS18BTECH11022 


## Files included:
* Makefile
* main.py
* firewall.py
* firewall_utils.py
* rules_io.py
* protocols.py
* cipher.py
* rules.json

## Dependencies:
* Python 3 runtime
* Python libraries: socket, sys, os, json, getpass, numpy, plotext, ipaddress, re, base64, hashlib, pycrypto, bisect, select, queue

## Instructions to setup and execute:
* Place all the relevent files in the same folder and execute the command ***"make"***.
* Following this, you can find the executable script firewall in the directory.
* Run ***"./firewall -help"*** to obtain information on the various usages of the program.
* Run ***"./firewall rules -f [rule_file_name] -create"*** to create a rule file for the firewall.
* Run ***"./firewall run -i [internal network interface] -e [external network interface]-f [path to rules] "*** to run the firewall between the internal and external interfaces.