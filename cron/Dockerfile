FROM alpine:latest

ARG duplicity_password
ARG duplicity_offsite_dest
ARG aws_access_key_id
ARG aws_secret_key

ARG cloudflare_email
ARG cloudflare_key
ARG cloudflare_domain
ARG cloudflare_subdomains

ENV PIP_BREAK_SYSTEM_PACKAGES=1

RUN apk update && apk upgrade && apk add duplicity py3-pip jq curl openssh rsync
RUN pip3 install boto3

COPY general/dotenv_writer/build/bin/dotenv_writer /bin/dotenv_writer
RUN chmod +x /bin/dotenv_writer

RUN dotenv_writer -D CLOUDFLARE_EMAIL=${cloudflare_email} \
    -D CLOUDFLARE_KEY=${cloudflare_key} \
    -D CLOUDFLARE_DOMAIN=${cloudflare_domain} \
    -D CLOUDFLARE_SUBDOMAINS=${cloudflare_subdomains} \
    -D DUPLICITY_PASSWORD=${duplicity_password} \
    -D DUPLICITY_OFFSITE_DEST=${duplicity_offsite_dest} \
    -D AWS_ACCESS_KEY_ID=${aws_access_key_id} \
    -D AWS_SECRET_ACCESS_KEY=${aws_secret_key} \
    --output /

ADD cron/duplicity /duplicity
RUN chmod +x /duplicity/run_dup_once.sh

COPY cron/cloudflare-dns/build/bin/cf_dyndns /bin/cf_dyndns
RUN chmod +x /bin/cf_dyndns

# ADD cron/run_hourly/ /etc/periodic/hourly/
RUN chmod +x /etc/periodic/hourly/* || true

ADD cron/backups /backups
RUN chmod +x /backups/* || true

RUN touch /var/log/cron.log
RUN (crontab -l 2>/dev/null; echo "0 0 * * 0 /backups/backup_ocis.sh > /proc/1/fd/1 2>/proc/1/fd/2") | crontab -
RUN (crontab -l 2>/dev/null; echo "0 0 * * 0 /backups/backup_jellyfin.sh > /proc/1/fd/1 2>/proc/1/fd/2") | crontab -
RUN (crontab -l 2>/dev/null; echo "10 0 * * 0 /duplicity/run_dup_once.sh > /proc/1/fd/1 2>/proc/1/fd/2") | crontab -
RUN (crontab -l 2>/dev/null; echo "*/30 * * * * RUST_LOG=info cf_dyndns --dotenv-dir / > /proc/1/fd/1 2>/proc/1/fd/2") | crontab -

CMD ["crond", "-f"]
