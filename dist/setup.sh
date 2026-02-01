#!/bin/bash

sudo apt update
sudo apt upgrade -y
sudo apt install -y \
    build-essential \
    clang \
    llvm \
    m4 \
    pkg-config \
    gnupg \
    git \
    libbpf-dev \
    libxdp-dev \
    libpcap-dev \
    libmnl-dev \
    bpftool \
    unzip \
    jq \
    wget \
    zsh \
    htop

wget -O - https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(grep -oP '(?<=UBUNTU_CODENAME=).*' /etc/os-release || lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt update && sudo apt install -y terraform

mkdir /tmp/aws-cli
curl "https://awscli.amazonaws.com/awscli-exe-linux-aarch64.zip" -o "/tmp/aws-cli/awscliv2.zip"
unzip /tmp/aws-cli/awscliv2.zip -d /tmp/aws-cli
sudo /tmp/aws-cli/aws/install

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
rustup component add rust-analyzer
