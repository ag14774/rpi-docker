#!/usr/bin/env sh

export PASSPHRASE="<duplicity-password>"

OFFSITE_FULL_EVERY="90D"
OFFSITE_KEEP_FULL=1
OFFSITE_DEST=<duplicity-offsite-dest>
# Example OFFSITE_DEST=gdrive://4543653-565gfdgdf.apps.googleusercontent.com?myDriveFolderID=543gfFG4gfdv54vfd44
# The googleusercontent.com url can be found in console.cloud.google.com under 'Client ID' in the Credentials tab
# The myDriveFolderID can be found in the url of google drive inside the folder you would like to backup your data
# e.g https://drive.google.com/drive/u/0/folders/543gfFG4gfdv54vfd44 <--folder id
# For service accounts the offise destination would look like: 
# gdrive://gdfgdf@gfdgdfs.iam.gserviceaccount.com/?myDriveFolderId=gfgrgeg43
VERBOSITY=3

(
flock -x 200

# Clean up any previously failed runs
GOOGLE_SERVICE_JSON_FILE=/duplicity/credentials.json \
  duplicity --verbosity=$VERBOSITY cleanup --force ${OFFSITE_DEST}

if [ $VERBOSITY -gt 0 ]; then
    echo "Performing an offsite backup to ${OFFSITE_DEST}"
fi
GOOGLE_SERVICE_JSON_FILE=/duplicity/credentials.json \
  duplicity \
    --verbosity=$VERBOSITY \
    --allow-source-mismatch \
    --full-if-older-than=$OFFSITE_FULL_EVERY \
    --exclude-filelist /duplicity/excludes \
    /mnt/backup ${OFFSITE_DEST}

if [ $VERBOSITY -gt 0 ]; then
    echo "Removing all but ${OFFSITE_KEEP_FULL} full backup from ${OFFSITE_DEST}"
fi
GOOGLE_SERVICE_JSON_FILE=/duplicity/credentials.json \
  duplicity --verbosity=$VERBOSITY \
    remove-all-but-n-full ${OFFSITE_KEEP_FULL} \
    --force ${OFFSITE_DEST}

)200>/mnt/backup/.lockfile
