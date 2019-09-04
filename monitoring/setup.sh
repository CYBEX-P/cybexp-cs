#!/bin/bash

# See https://docs.mongodb.com/charts/onprem/installation/
# for installation insructions

set -ex

sudo docker swarm init

sudo docker pull quay.io/mongodb/charts:19.06.1

sudo docker stack deploy -c docker-swarm.yml mongodb-charts

set +e # Key backups are optional and only need to happen once

mkdir /tmp/charts-keys-backup
docker run -it --volume mongodb-charts_keys:/volume --volume /tmp/charts-keys-backup:/backup alpine sh -c 'cp /volume/* /backup'

# Don't forget to create users:
# docker exec -it \
#       $(docker container ls --filter name=_charts -q) \
#       charts-cli add-user --first-name "<First>" --last-name "<Last>" \
#       --email "<user@example.com>" --password "<Password>" \
#       --role "<UserAdmin|User>"
