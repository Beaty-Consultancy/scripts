FROM golang:alpine

LABEL maintainer="Ahmed <ahmed@beatyconsultancy.co.uk>"

RUN apk add --no-cache \
  curl \
  gcompat \
  git \
  idn2-utils \
  jq \
  openssh

COPY tofu /usr/local/bin/tofu

RUN tofu --version

WORKDIR /

COPY ghb-tofu.sh /usr/bin/ghb-tofu
RUN chmod +x /usr/bin/ghb-tofu

# Override ENTRYPOINT since hashicorp/terraform uses `terraform`
ENTRYPOINT []