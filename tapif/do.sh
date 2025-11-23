sudo ip tuntap add dev tap0 mode tap user $(whoami)
sudo ip addr add 192.168.1.1/24 dev tap0
sudo ip link set tap0 up
ip addr show tap0

