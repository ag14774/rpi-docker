FROM traefik:v2.5

ARG traefik_email

COPY ./traefik.toml /traefik.toml
RUN sed -i "s|<traefik-email>|${traefik_email}|g" /traefik.toml
