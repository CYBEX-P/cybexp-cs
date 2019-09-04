#!/bin/bash

if [[ -z $(which sops) ]]; then
    echo "Installing sops to decrypt at-rest keys."
    wget https://github.com/mozilla/sops/releases/download/3.3.1/sops_3.3.1_amd64.deb -O /tmp/sops.deb
    dpkg -i /tmp/sops.deb
fi

sops -d config.enc.json --keyservice cybexp1.acs.unr.edu:5001 > config.json

sudo docker build . -t cybex-input:latest
