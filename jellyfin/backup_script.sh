#!/usr/bin/env bash

mkdir -p /mnt/backup/jellyfin
rsync -Aax --ignore-missing-args /config/ /mnt/backup/jellyfin/jellyfin_config
