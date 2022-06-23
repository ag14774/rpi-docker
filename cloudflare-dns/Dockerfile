FROM ubuntu:latest

ARG cloudflare_email
ARG cloudflare_key
ARG cloudflare_domain
ARG cloudflare_subdomains

RUN apt-get update && apt-get -y install cron jq curl

COPY ./cloudflare-dyndns.sh /cloudflare-dyndns.sh
RUN sed -i "s|<cloudflare-email>|${cloudflare_email}|g" /cloudflare-dyndns.sh
RUN sed -i "s|<cloudflare-key>|${cloudflare_key}|g" /cloudflare-dyndns.sh
RUN sed -i "s|<cloudflare-domain>|${cloudflare_domain}|g" /cloudflare-dyndns.sh
RUN sed -i "s|<cloudflare-subdomains>|${cloudflare_subdomains}|g" /cloudflare-dyndns.sh

RUN chmod +x /cloudflare-dyndns.sh
RUN touch /var/log/cron.log
RUN (crontab -l 2>/dev/null; echo "*/2 * * * * /cloudflare-dyndns.sh > /proc/1/fd/1 2>/proc/1/fd/2") | crontab -
CMD ["cron", "-f"]
