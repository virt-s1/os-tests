#!/bin/bash


########################################################################################
## Description:
## 	Test scrip test_pktgen.sh in the VM.
##
## Revision:
## 	v1.0.0 - boyang - 03/09/2018 - Build script.
## 	v1.0.1 - boyang - 05/14/2019 - Get VM's IP dynamically.
##  v1.0.2 - minl - 07/25/2022 - Update script for adding to os-tests.
########################################################################################




########################################################################################
# Main script body
########################################################################################
# Get NIC interface
nic=`ls /sys/class/net | grep ^e[tn][hosp]`
echo "DEBUG: nic: $nic"
echo "DEBUG: nic: $nic"


# NIC hardware address
hwadd=`cat /sys/class/net/$nic/address`
echo "INFO: hwadd is $hwadd"
echo "INFO: hwadd is $hwadd"


# NIC IP address
ipadd=`ip -f inet add | grep $nic | grep inet | awk '{print $2}' | awk -F "/" '{print $1}'`
echo "DEBUG: ipadd: $ipadd"
echo "DEBUG: ipadd: $ipadd"
if [ "x$ipadd" -eq "x" ]
    then
	echo "ERROR: Get VM's IP failed"
	echo "ERROR: Get VM's IP failed"
	SetTestStateAborted
        exit 1
fi


echo "INFO: Will modprobe pktgen"
echo "INFO: Will modprobe pktgen"
modprobe pktgen
if [ $? -ne 0 ]; then
    echo "ERROR: Before RHEL8.1.0 DISTRO, modprobe pktgen directlly. After RHEL8.1.0, it has been moved to kernel self test package, should install kernel-module-internal package from brew"
    echo "ERROR: Before RHEL8.1.0 DISTRO, modprobe pktgen directlly. After RHEL8.1.0, it has been moved to kernel self test package, should install kernel-module-internal package from brew"
    
    echo "INFO: Try to install a kernel-module-internal in RHEL-8.1.0 or later"
    echo "INFO: Try to install a kernel-module-internal in RHEL-8.1.0 or later"

    url_pre="http://download.eng.bos.redhat.com/brewroot/vol/rhel-$1/packages/kernel"
    ver=`uname -r | awk -F "-" {'print $1'}`
    rel=`uname -r | awk -F "-" {'print $2'}`
    rel1=${rel%.*}
    arch=${rel##*.}
    url="${url_pre}/${ver}/${rel1}/${arch}/kernel-modules-internal-${ver}-${rel1}.${arch}.rpm"
    echo "DEBUG: url: $url"
    echo "DEBUG: url: $url"

    yum -y install $url
    if [ $? -ne 0 ]; then
	echo "ERROR: Try to install kernel-module-internal failed"        
	echo "ERROR: Try to install kernel-module-internal failed"        
        exit 1
    else
	echo "INFO: Try modprobe pktgen again after installation" 
	echo "INFO: Try modprobe pktgen again after installation" 
	modprobe pktgen
        if [ $? -ne 0 ]; then
	    echo "ERROR: Modprobe pktgen failed after installation" 
	    echo "ERROR: Modprobe pktgen failed after installation" 
            exit 1
	fi
    fi
fi 


function pgset() {
    local result
    echo $1 > $PGDEV
    result=`cat $PGDEV | fgrep "Result: OK:"`
    if [ "$result" = "" ]; then
         cat $PGDEV | fgrep Result:
    fi
}


function pg() {
    echo inject > $PGDEV
    cat $PGDEV
}


# Config Start Here
# Thread config
# Each CPU has own thread. One CPU exammple. Add the name the guest nic, such as eth0
PGDEV=/proc/net/pktgen/kpktgend_0
echo "INFO: Removing all devices"
echo "INFO: Removing all devices"
pgset "rem_device_all"

# Change to the name of nic
echo "INFO: Adding $nic"
echo "INFO: Adding $nic"
pgset "add_device $nic"

# Setting max_before_softirq
echo "INFO: Setting max_before_softirq 10000"
echo "INFO: Setting max_before_softirq 10000"
pgset "max_before_softirq 10000"

# Device config
# Delay 0 means maximum speed.
CLONE_SKB="clone_skb 1000000"

# NIC adds 4 bytes CRC
PKT_SIZE="pkt_size 60"

# COUNT 0 means forever
COUNT="count 10000000"
DELAY="delay 0"
PGDEV=/proc/net/pktgen/$nic
echo "INFO: Configuring $PGDEV"
echo "INFO: Configuring $PGDEV"
pgset "$COUNT"
pgset "$CLONE_SKB"
pgset "$PKT_SIZE"
pgset "$DELAY"
pgset "dst $ipadd" # IP address of NIC you want to test, such as eth0.
pgset "dst_mac $hwadd" # MAC address of the name of NIC you want to test, such as eth0.


# Time to run
PGDEV=/proc/net/pktgen/pgctrl
echo "INFO: Running... ctrl^C to stop"
echo "INFO: Running... ctrl^C to stop"

pgset "start"

echo "INFO: Done"
echo "INFO: Done"

echo "INFO: Result is stored in /proc/net/pktgen/$nic"
echo "INFO: Result is stored in /proc/net/pktgen/$nic"


# Check the result
cat /proc/net/pktgen/$nic | grep "Result: OK"
if [ $? -eq 0 ]
    then
	echo "INFO: Case passed."
	echo "INFO: Case passed."
	#SetTestStateCompleted
    exit 0
else
	echo "ERROR: Cases failed."
	echo "ERROR: Cases failed."
	#SetTestStateFailed
	exit 1
fi
