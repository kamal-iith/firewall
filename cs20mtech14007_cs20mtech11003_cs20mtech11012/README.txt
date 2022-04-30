********************************************************************************************************************************************
FIREWALL <README>

Submitted by Tahir Ahmed Shaik (CS20MTECH14007), Pratik M. lahase (CS20MTECH11003) , Jaykishan Pipaliya (CS20MTECH11012)

Date : 01/05/2021
********************************************************************************************************************************************

The Program is written in python and the entire source code is included in the "firewall.py" program code.

VM Requirements:

2 VM's , 1 Host machine .
VM's installed and managed using virt-manager (https://virt-manager.org/)

--------------------------------------------------------------------------------------------------------------------------------------------
1.To run the simple firewall for TASK1 ( For firewall with pre defined/ pre hot coded logic), the following command is run.

COMMAND : sudo firewall.py simple_firewall <external_host_interface> <internal_host_interface>
--------------------------------------------------------------------------------------------------------------------------------------------
2. To run the Advanced firewall for TASK2,3 and 4 ( For Extended firewall with CLI, Dynamic Rule management, performance analysis and dos attack detection), the following command is run.

COMMAND : sudo firewall.py adv_firewall <external_host_interface> <internal_host_interface>

--------------------------------------------------------------------------------------------------------------------------------------------

*NOTE* --> sudo is required for running program for raw sockets.

python libraries requirements
1. matplotlib
2. pyfiglet
3. socket
4. json
5. numpy


 
