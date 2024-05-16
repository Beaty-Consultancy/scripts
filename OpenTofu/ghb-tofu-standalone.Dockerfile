FROM golang:latest

LABEL maintainer="Ahmed <ahmed@beatyconsultancy.co.uk>"

RUN apt update && apt install \
  curl \
  git \
  jq \
  unzip

# Install AWS CLI
RUN curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" && \
    unzip awscliv2.zip && \
    ./aws/install

# Clean up
RUN rm awscliv2.zip && \
    rm -rf aws

WORKDIR /tmp
RUN git clone https://github.com/opentofu/opentofu.git
RUN cd opentofu/cmd/tofu && go build .
WORKDIR /tmp/opentofu/cmd/tofu
RUN cp tofu /usr/local/bin
RUN export PATH=$PATH:/usr/local/bin/tofu

WORKDIR /

COPY ghb-tofu.sh /usr/bin/ghb-tofu
RUN chmod +x /usr/bin/ghb-tofu

# Override ENTRYPOINT since hashicorp/terraform uses `terraform`
ENTRYPOINT []