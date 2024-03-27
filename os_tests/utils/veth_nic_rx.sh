set -x
# this script reproduce RHEL-14286, the connection might loss for a while if run test over active interface
if [ -z $1 ]; then
    nic="eth0"
else
    nic=$1
fi
# run two loops for better reproducer
for i in {1..2}; do
    ip link add veth0 type veth peer name veth1
    ethtool -L veth0 tx 16
    ethtool -L veth1 tx 16

    nmcli conn add type bridge con-name br1 ifname br1
    nmcli conn modify br1 ipv4.addresses '192.168.1.1/24'
    nmcli conn modify br1 ipv4.gateway '192.168.1.1'
    nmcli conn modify br1 ipv4.dns '192.168.1.1'
    nmcli conn modify br1 ipv4.method manual
    nmcli conn add type ethernet slave-type bridge con-name bridge-br2 ifname veth1 master br1
    nmcli conn add type ethernet slave-type bridge con-name bridge-br3 ifname $nic master br1
    nmcli conn up bridge-br2
    nmcli conn up bridge-br3
    nmcli conn up br1

    nmcli conn add type bridge con-name br0 ifname br0
    nmcli conn add type ethernet slave-type bridge con-name bridge-br0 ifname veth0 master br0
    nmcli conn add type ethernet slave-type bridge con-name bridge-br1 ifname $nic master br0
    ip link set veth0 up
    ip link set veth1 up
    nmcli conn up bridge-br0
    nmcli conn up bridge-br1
    nmcli conn up br0
    ping 8.8.8.8 -c 8
    sleep 160
    ping 8.8.8.8 -c 8
    nmcli connection delete bridge-br1
    nmcli connection delete bridge-br0
    nmcli connection delete bridge-br3
    nmcli connection delete bridge-br2
    nmcli connection delete br0
    nmcli connection delete br1
    ip link delete veth0
    ip link delete veth1
done
