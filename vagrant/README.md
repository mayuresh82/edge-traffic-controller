# Vagrant + Virtualbox setup

This sample topology includes a Cumulus VX Linux switch , a Juniper vQFX 10K (RE + PFE) and a couple of hosts.

- Install the boxes using:
`vagrant box add juniper/vqfx10k-re`
`vagrant box add juniper/vqfx10k-pfe`
`vagrant box add CumulusCommunity/cumulus-vx`
`vagrant box add ubuntu/bionic64`

- Boot up the topology using `vagrant up` . Vagrant should automatically install its ssh keys into the VMs to allow SSH without passwords.

- Log into the Cumulus VX and enable host sflow:

```
vagrant ssh cumos1

MOD_STATISTIC="-m statistic --mode random --probability 0.001"
NFLOG_CONFIG="--nflog-group 5 --nflog-prefix SFLOW"

sudo iptables -t mangle -I POSTROUTING -j NFLOG $MOD_STATISTIC $NFLOG_CONFIG
sudo iptables -t mangle -I INPUT -j NFLOG $MOD_STATISTIC $NFLOG_CONFIG

sudo service hsflowd start

```
