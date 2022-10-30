FROM traefik:v2.9.4

ARG traefik_email

COPY ./traefik.toml /traefik.toml
RUN sed -i "s|<traefik-email>|${traefik_email}|g" /traefik.toml
