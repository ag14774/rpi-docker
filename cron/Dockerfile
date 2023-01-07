FROM alpine:latest

ARG duplicity_password
ARG duplicity_offsite_dest
ARG aws_access_key_id
ARG aws_secret_key

ARG cloudflare_email
ARG cloudflare_key
ARG cloudflare_domain
ARG cloudflare_subdomains

RUN apk update && apk upgrade && apk add duplicity jq curl openssh

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

ADD cron/run_hourly/ /etc/periodic/hourly/
RUN chmod +x /etc/periodic/hourly/* || true

RUN touch /var/log/cron.log
RUN (crontab -l 2>/dev/null; echo "0 0 * * 0 /duplicity/run_dup_once.sh > /proc/1/fd/1 2>/proc/1/fd/2") | crontab -
RUN (crontab -l 2>/dev/null; echo "*/30 * * * * cf_dyndns --dotenv-dir / > /proc/1/fd/1 2>/proc/1/fd/2") | crontab -

CMD ["crond", "-f"]
