FROM golang:alpine

LABEL maintainer="Ahmed <ahmed@beatyconsultancy.co.uk>"

RUN apk add --no-cache \
  curl \
  gcompat \
  git \
  idn2-utils \
  jq \
  openssh

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