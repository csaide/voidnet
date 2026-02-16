#!/bin/bash

sudo apt update
sudo apt install -y \
    build-essential \
    clang \
    llvm \
    m4 \
    pkg-config \
    git \
    gnupg \
    libbpf-dev \
    libxdp-dev \
    libpcap-dev \
    libmnl-dev \
    bpftool \
    unzip \
    jq \
    wget \
    zsh

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
cargo +stable install cargo-llvm-cov --locked

curl -fsSL https://claude.ai/install.sh | bash

cat >> ~/.zshrc << EOF
export PATH="$HOME/.local/bin:$PATH"

SSH_ENV="$HOME/.ssh/agent-environment"

function start_agent {
    echo "Initialising new SSH agent..."
    /usr/bin/ssh-agent | sed 's/^echo/#echo/' >"$SSH_ENV"
    echo succeeded
    chmod 600 "$SSH_ENV"
    . "$SSH_ENV" >/dev/null
    /usr/bin/ssh-add;
}

# Source SSH settings, if applicable

if [ -f "$SSH_ENV" ]; then
    . "$SSH_ENV" >/dev/null
    #ps $SSH_AGENT_PID doesn't work under Cygwin
    ps -ef | grep $SSH_AGENT_PID | grep ssh-agent$ >/dev/null || {
        start_agent
    }
else
    start_agent
fi

EOF
