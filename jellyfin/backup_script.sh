#!/usr/bin/env bash

mkdir -p /mnt/backup/jellyfin
rsync -Aax --ignore-missing-args /mnt/data/jellyfin_config /mnt/backup/jellyfin/
