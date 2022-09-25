#!/usr/bin/env sh

source /.env

export PASSPHRASE=${DUPLICITY_PASSWORD}
export OFFSITE_DEST=${DUPLICITY_OFFSITE_DEST}

OFFSITE_FULL_EVERY="90D"
OFFSITE_KEEP_FULL=1
VERBOSITY=3

(
flock -x 200

# Clean up any previously failed runs
duplicity --verbosity=$VERBOSITY cleanup --force ${OFFSITE_DEST} --s3-endpoint-url=https://storage.googleapis.com

if [ $VERBOSITY -gt 0 ]; then
    echo "Performing an offsite backup to ${OFFSITE_DEST}"
fi
duplicity \
  --verbosity=$VERBOSITY \
  --allow-source-mismatch \
  --volsize=1000 \
  --full-if-older-than=$OFFSITE_FULL_EVERY \
  --exclude-filelist /duplicity/excludes \
  --s3-endpoint-url=https://storage.googleapis.com \
  /mnt/backup ${OFFSITE_DEST}

if [ $VERBOSITY -gt 0 ]; then
    echo "Removing all but ${OFFSITE_KEEP_FULL} full backup from ${OFFSITE_DEST}"
fi
duplicity --verbosity=$VERBOSITY \
  remove-all-but-n-full ${OFFSITE_KEEP_FULL} \
  --s3-endpoint-url=https://storage.googleapis.com \
  --force ${OFFSITE_DEST}

)200>/mnt/backup/.lockfile
