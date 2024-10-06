#!/usr/bin/env bash

mkdir -p /mnt/backup/owncloud
(
flock -x 200
curl -X POST http://socket-proxy:2375/v1.44/containers/ocis/pause
rsync -Aax --ignore-missing-args /mnt/ocis_config /mnt/ocis_data /mnt/backup/owncloud/
)200>/mnt/backup/.lockfile

curl -X POST http://socket-proxy:2375/v1.44/containers/ocis/unpause
