# Usage: docker build --build-arg BASE=ubuntu:24.04 -f tests/Dockerfile -t nginx-backtrace-ng:ubuntu .
ARG BASE=ubuntu:24.04
FROM ${BASE}

ARG NGINX_VERSION=1.31.7
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential ca-certificates curl libunwind-dev libpcre2-dev zlib1g-dev procps fcgiwrap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
RUN curl -fsSL https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz | tar xz --strip-components=1

COPY config ngx_backtrace_module.c /module/

RUN ./configure --prefix=/opt/nginx --with-cc-opt="-g -O0" --add-module=/module \
    && make -j"$(nproc)" && make install

COPY tests/run.sh /tests/run.sh
COPY tests/cgi-bin /tests/cgi-bin
RUN chmod +x /tests/cgi-bin/*.cgi
CMD ["/tests/run.sh"]
