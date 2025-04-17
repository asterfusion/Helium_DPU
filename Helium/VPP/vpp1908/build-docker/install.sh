#!/bin/bash -e

# apt-get update
apt-get --allow-releaseinfo-change update && \
    apt-get install -y \
    rsyslog \
    libpython3-stdlib \
    libmbedcrypto3 \
    libmbedtls12 \
    libmbedx509-0 \
    python3 \
    python3-minimal \
    python3-cffi \
    python3-cffi-backend \
    python3-ply \
    python3-pycparser \
    python-cffi \
    python-cffi-backend \
    python-ply \
    python-pycparser \
    python-ipaddress

# install VPP debs
dpkg -i /tmp/debs/*.deb

# Clean up
apt-get clean -y      && \
apt-get autoclean -y  && \
apt-get autoremove -y && \
rm -rf ~/.cache && \
rm -rf /tmp/*.deb

