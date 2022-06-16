ARG owncloud_version=latest
FROM owncloud/server:${owncloud_version}

COPY ./backup_script.sh /backup_script.sh
RUN sed -i "s|<cloudflare-email>|${cloudflare_email}|g" /cloudflare-dyndns.sh
RUN sed -i "s|<cloudflare-key>|${cloudflare_key}|g" /cloudflare-dyndns.sh
RUN sed -i "s|<cloudflare-domain>|${cloudflare_domain}|g" /cloudflare-dyndns.sh
RUN sed -i "s|<cloudflare-subdomains>|${cloudflare_subdomains}|g" /cloudflare-dyndns.sh

RUN chmod +x /backup_script.sh

RUN (crontab -u www-data -l 2>/dev/null; echo "0 0 * * * /backup_script.sh") | crontab -u www-data -
