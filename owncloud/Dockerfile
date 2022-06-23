ARG owncloud_version=latest
FROM owncloud/server:${owncloud_version}

RUN touch /var/log/rsync.log
RUN chown www-data:www-data /var/log/rsync.log
RUN chmod +w /var/log/rsync.log

COPY ./backup_script.sh /backup_script.sh
RUN chown www-data:www-data /backup_script.sh
RUN chmod +x /backup_script.sh

COPY ./backup_cron /etc/cron.d/backup_cron
RUN chmod 644 /etc/cron.d/backup_cron

