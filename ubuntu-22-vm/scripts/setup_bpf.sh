#!/bin/bash

sudo apt install -y build-essential autoconf git curl libpcap-dev unzip

sudo apt install clang llvm libelf-dev libpcap-dev gcc-multilib build-essential
sudo apt install -y linux-tools-$(uname -r) linux-headers-$(uname -r) linux-tools-common linux-tools-generic
sudo apt install -y bpftool libbpf-dev


# install go
wget "https://go.dev/dl/go1.18.3.linux-amd64.tar.gz"
sudo tar -C /usr/local/ -xzf go1.18.3.linux-amd64.tar.gz 
rm go1.18.3.linux-amd64.tar.gz
echo "export PATH=\$PATH:/usr/local/go/bin" >> /home/vagrant/.bashrc
echo "export GOPATH=\$HOME/go" >> /home/vagrant/.bashrc
echo "export PATH=\$PATH:\$GOPATH/bin" >> /home/vagrant/.bashrc
export PATH=$PATH:/usr/local/go/bin

echo
echo "---------- Linux Config ----------"
grep -i CONFIG_BPF /boot/config-$(uname -r)
grep -i CONFIG_XDP_SOCKETS /boot/config-$(uname -r)
echo