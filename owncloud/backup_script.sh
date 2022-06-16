#!/usr/bin/env bash

mkdir -p /mnt/backup/owncloud
(
flock -x 200
occ maintenance:mode --on
rsync -Aax config data apps apps-external /mnt/backup/owncloud/
mysqldump --single-transaction -h mariadb -u owncloud --password=owncloud owncloud --column-statistics=0 > /mnt/backup/owncloud/owncloud-dbbackup_`date +"%Y%m%d"`.bak
)200>/mnt/backup/.lockfile

occ maintenance:mode --off
