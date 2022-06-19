#!/usr/bin/env bash

export PASSPHRASE="<duplicity-password>"

OFFSITE_FULL_EVERY="90D"
OFFSITE_KEEP_FULL=1
OFFSITE_DEST=<duplicity-offsite-dest>
VERBOSITY=3

(
flock -x 200

# Clean up any previously failed runs
GOOGLE_DRIVE_SETTINGS=/duplicity/credentials duplicity --verbosity=0 cleanup --force ${OFFSITE_DEST}

if [ $VERBOSITY -gt 0 ]; then
    echo "Performing an offsite backup to ${OFFSITE_DEST}"
fi
GOOGLE_DRIVE_SETTINGS=/duplicity/credentials duplicity \
    --verbosity=$VERBOSITY \
    --allow-source-mismatch \
    --full-if-older-than=$OFFSITE_FULL_EVERY \
    --exclude-filelist /duplicity/excludes \
    /backup ${OFFSITE_DEST}

if [ $VERBOSITY -gt 0 ]; then
    echo "Removing all but ${OFFSITE_KEEP_FULL} full backup from ${OFFSITE_DEST}"
fi
GOOGLE_DRIVE_SETTINGS=/duplicity/credentials duplicity --verbosity=$VERBOSITY \
    remove-all-but-n-full ${OFFSITE_KEEP_FULL} \
    --force ${OFFSITE_DEST}

)200>/mnt/backup/.lockfile
