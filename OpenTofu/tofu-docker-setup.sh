#!/bin/bash

# Update the package index
sudo apt-get update
sudo apt-get install -y unzip

# Install AWS CLI
wget https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip
unzip awscli-exe-linux-x86_64.zip
sudo ./aws/install

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh

# Install Go
wget https://go.dev/dl/go1.24.1.linux-amd64.tar.gz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.24.1.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
go version

# Get latest release version
LATEST_VERSION=$(curl -s https://api.github.com/repos/opentofu/opentofu/releases/latest | grep 'tag_name' | cut -d'"' -f4)

# Download and extract the source code
wget https://github.com/opentofu/opentofu/archive/refs/tags/${LATEST_VERSION}.tar.gz
tar -xzf ${LATEST_VERSION}.tar.gz
cd opentofu-${LATEST_VERSION}/cmd/tofu

# Build the Go project
go build .

# Clone the ghb-tofu.Dockerfile from the provided gist
git clone https://gist.github.com/e8dfbdc0cd170ee5239833d5399abe30.git
cp e8dfbdc0cd170ee5239833d5399abe30/ghb-tofu.Dockerfile .

# Clone the ghb-tofu.sh from the provided gist
git clone https://gist.github.com/3652c4cfc1d0daec822430cba3fd3a0c.git
cp 3652c4cfc1d0daec822430cba3fd3a0c/ghb-tofu.sh .

# Get the tofu version
TOFU_VERSION=$(./tofu --version | head -n1 | awk '{print $2}')

# Build the Docker image
docker build -f ghb-tofu.Dockerfile -t ghb-tofu:latest .
docker build -f ghb-tofu.Dockerfile -t ghb-tofu:$TOFU_VERSION .

# Tag the Docker image
docker tag ghb-tofu:latest public.ecr.aws/c3w2w7c4/ghb-tofu:latest
docker tag ghb-tofu:$TOFU_VERSION public.ecr.aws/c3w2w7c4/ghb-tofu:$TOFU_VERSION

# Authenticate Docker with ECR and push the image
aws ecr-public get-login-password --region eu-west-2 | docker login --username AWS --password-stdin public.ecr.aws/c3w2w7c4
docker push public.ecr.aws/c3w2w7c4/ghb-tofu:latest
docker push public.ecr.aws/c3w2w7c4/ghb-tofu:$TOFU_VERSION