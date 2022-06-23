ARG owncloud_version=latest
FROM owncloud/server:${owncloud_version}

COPY ./backup_script.sh /backup_script.sh
RUN chown www-data:www-data /backup_script.sh
RUN chmod +x /backup_script.sh

RUN (crontab -u www-data -l 2>/dev/null; echo "0 0 * * * /backup_script.sh > /proc/1/fd/1 2>/proc/1/fd/2") | crontab -u www-data -
