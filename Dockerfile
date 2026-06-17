# Build ngx_mail_sni_module.so against the official nginx image's exact version,
# then produce a minimal image that has the module ready to load.
#
#   docker build -t nginx-mail-sni .
#   # the module is at /etc/nginx/modules/ngx_mail_sni_module.so
#   # add to nginx.conf:  load_module modules/ngx_mail_sni_module.so;
#
# ARG NGINX_IMAGE lets you match your runtime (must be built --with-compat,
# which the official images are).

ARG NGINX_IMAGE=nginx:stable

FROM ${NGINX_IMAGE} AS nginxbase
RUN nginx -v 2>&1 | sed -n 's:.*nginx/\([0-9.]*\).*:\1:p' > /nginx_version

FROM debian:trixie AS build
COPY --from=nginxbase /nginx_version /nginx_version
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        build-essential curl ca-certificates libpcre2-dev zlib1g-dev libssl-dev \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY ngx_mail_sni_module.c config /src/module/
RUN set -eux; \
    V="$(cat /nginx_version)"; \
    curl -fsSLO "https://nginx.org/download/nginx-${V}.tar.gz"; \
    tar xzf "nginx-${V}.tar.gz"; \
    cd "nginx-${V}"; \
    ./configure --with-compat --with-mail --with-mail_ssl_module \
                --add-dynamic-module=/src/module; \
    make modules; \
    cp objs/ngx_mail_sni_module.so /ngx_mail_sni_module.so

FROM ${NGINX_IMAGE}
COPY --from=build /ngx_mail_sni_module.so /etc/nginx/modules/ngx_mail_sni_module.so
