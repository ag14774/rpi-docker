FROM alpine:latest

ARG duplicity_password
ARG duplicity_offsite_dest

ARG cloudflare_email
ARG cloudflare_key
ARG cloudflare_domain
ARG cloudflare_subdomains

RUN apk update && apk upgrade && apk add py3-pip duplicity jq curl
RUN pip3 install google-api-python-client google-auth-oauthlib requests

ADD duplicity /duplicity
RUN sed -i "s|<duplicity-password>|${duplicity_password}|g" /duplicity/run_dup_once.sh
RUN sed -i "s|<duplicity-offsite-dest>|${duplicity_offsite_dest}|g" /duplicity/run_dup_once.sh
RUN chmod +x /duplicity/run_dup_once.sh

ADD cloudflare-dns /cloudflare-dns
RUN sed -i "s|<cloudflare-email>|${cloudflare_email}|g" /cloudflare-dns/cloudflare-dyndns.py
RUN sed -i "s|<cloudflare-key>|${cloudflare_key}|g" /cloudflare-dns/cloudflare-dyndns.py
RUN sed -i "s|<cloudflare-domain>|${cloudflare_domain}|g" /cloudflare-dns/cloudflare-dyndns.py
RUN sed -i "s|<cloudflare-subdomains>|${cloudflare_subdomains}|g" /cloudflare-dns/cloudflare-dyndns.py
RUN chmod +x /cloudflare-dns/cloudflare-dyndns.py

RUN touch /var/log/cron.log
RUN (crontab -l 2>/dev/null; echo "0 0 * * * /duplicity/run_dup_once.sh > /proc/1/fd/1 2>/proc/1/fd/2") | crontab -
RUN (crontab -l 2>/dev/null; echo "*/30 * * * * /cloudflare-dns/cloudflare-dyndns.py > /proc/1/fd/1 2>/proc/1/fd/2") | crontab -

CMD ["crond", "-f"]
