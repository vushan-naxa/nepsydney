#!/bin/bash

pkill -f uwsgi -9
cd /srv/Projects/naxa-backend-boilerplate
git pull
docker-compose up --build -d
docker image prune -a --filter "until=24h" -f