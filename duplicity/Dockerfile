FROM alpine:latest

ARG duplicity_password
ARG duplicity_offsite_dest

RUN apk update && apk upgrade && apk add py3-pip duplicity
RUN pip3 install google-auth-oauthlib

ADD duplicity /duplicity
RUN sed -i "s|<duplicity-password>|${duplicity_password}|g" /duplicity/run_dup_once.sh
RUN sed -i "s|<duplicity-offsite-dest>|${duplicity_offsite_dest}|g" /duplicity/run_dup_once.sh

RUN chmod +x /duplicity/run_dup_once.sh

RUN touch /var/log/cron.log
RUN (crontab -l 2>/dev/null; echo "0 0 * * * /duplicity/run_dup_once.sh > /proc/1/fd/1 2>/proc/1/fd/2") | crontab -

CMD ["crond", "-f"]
