ARG VERSION=

FROM ubuntu:24.04

# Set timezone
RUN ln -snf /usr/share/zoneinfo/UTC /etc/localtime && echo UTC > /etc/timezone

# Update packages
RUN apt-get update && apt-get -y dist-upgrade

# Copy ic-gateway package
COPY ic-gateway_${VERSION}_amd64.deb /tmp

# Install it
RUN apt install /tmp/ic-gateway_${VERSION}_amd64.deb
