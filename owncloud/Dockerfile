ARG owncloud_version=latest
FROM owncloud/server:${owncloud_version}

COPY ./backup_script.sh /backup_script.sh
RUN chown root:root /backup_script.sh
RUN chmod +x /backup_script.sh

COPY ./backup_cron /etc/cron.d/backup_cron
RUN chmod 644 /etc/cron.d/backup_cron

