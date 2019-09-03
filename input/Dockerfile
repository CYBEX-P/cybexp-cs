FROM ubuntu:18.04

RUN apt-get update

RUN apt-get install -y python3.6 python3.6-dev python3-pip

RUN python3 -m pip install lomond pymisp requests

RUN mkdir /var/lib/cybexp

COPY input.py /var/lib/cybexp/
COPY plugin/ /var/lib/cybexp/plugin/

COPY config.json /var/lib/cybexp/

CMD cd /var/lib/cybexp && ./input.py
