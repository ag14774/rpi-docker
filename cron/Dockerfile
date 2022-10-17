FROM alpine:latest

ARG duplicity_password
ARG duplicity_offsite_dest
ARG gs_access_key_id
ARG gs_secret_key

ARG cloudflare_email
ARG cloudflare_key
ARG cloudflare_domain
ARG cloudflare_subdomains

RUN apk update && apk upgrade && apk add py3-pip duplicity jq curl openssh
RUN pip3 install boto3 requests python-dotenv

COPY general/dotenv_writer/target/aarch64-unknown-linux-musl/release/dotenv_writer /bin/dotenv_writer
RUN chmod +x /bin/dotenv_writer

RUN dotenv_writer -D CLOUDFLARE_EMAIL=${cloudflare_email} \
    -D CLOUDFLARE_KEY=${cloudflare_key} \
    -D CLOUDFLARE_DOMAIN=${cloudflare_domain} \
    -D CLOUDFLARE_SUBDOMAINS=${cloudflare_subdomains} \
    -D DUPLICITY_PASSWORD=${duplicity_password} \
    -D DUPLICITY_OFFSITE_DEST=${duplicity_offsite_dest} \
    -D AWS_ACCESS_KEY_ID=${gs_access_key_id} \
    -D AWS_SECRET_ACCESS_KEY=${gs_secret_key} \
    --output /

ADD cron/duplicity /duplicity
RUN chmod +x /duplicity/run_dup_once.sh

COPY cron/cloudflare-dns/target/aarch64-unknown-linux-musl/release/cf_dyndns /bin/cf_dyndns
RUN chmod +x /bin/cf_dyndns

ADD cron/run_hourly/ /etc/periodic/hourly/
RUN chmod +x /etc/periodic/hourly/*

RUN touch /var/log/cron.log
RUN (crontab -l 2>/dev/null; echo "0 0 * * 0 /duplicity/run_dup_once.sh > /proc/1/fd/1 2>/proc/1/fd/2") | crontab -
RUN (crontab -l 2>/dev/null; echo "*/30 * * * * cf_dyndns --dotenv-dir / > /proc/1/fd/1 2>/proc/1/fd/2") | crontab -

CMD ["crond", "-f"]
