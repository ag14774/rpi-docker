FROM tecnativa/docker-socket-proxy

ENV ALLOW_POST_PAUSE=0
ENV ALLOW_POST_UNPAUSE=0

RUN sed -i -e '/bind/a\' -e '    http-request allow if { path,url_dec -m reg -i ^(/v[\d\.]+)?/containers/[a-zA-Z0-9_.-]+/pause } { env(ALLOW_POST_PAUSE) -m bool }' /usr/local/etc/haproxy/haproxy.cfg.template
RUN sed -i -e '/bind/a\' -e '    http-request allow if { path,url_dec -m reg -i ^(/v[\d\.]+)?/containers/[a-zA-Z0-9_.-]+/unpause } { env(ALLOW_POST_UNPAUSE) -m bool }' /usr/local/etc/haproxy/haproxy.cfg.template
