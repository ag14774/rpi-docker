FROM ubuntu:latest

ARG client_id
ARG client_secret
ARG duplicity_password
ARG duplicity_offsite_dest

RUN apt-get update && apt-get -y install duplicity python3-pydrive

ADD duplicity /duplicity
RUN sed -i "s|<client-id>|${client_id}|g" /duplicity/credentials
RUN sed -i "s|<client-secret>|${client_secret}|g" /duplicity/credentials
RUN sed -i "s|<duplicity-password>|${duplicity_password}|g" /duplicity/run_dup_once.sh
RUN sed -i "s|<duplicity-offsite-dest>|${duplicity_offsite_dest}|g" /duplicity/run_dup_once.sh

RUN chmod +x /duplicity/run.sh
RUN chmod +x /duplicity/run_dup_once.sh

RUN touch /var/log/cron.log
RUN (crontab -l 2>/dev/null; echo "0 0 * * * /duplicity/run_dup_once.sh  > /proc/1/fd/1 2>/proc/1/fd/2") | crontab -

CMD ["/duplicity/run.sh"]
