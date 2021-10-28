FROM docker.io/alpine:latest
MAINTAINER Benedikt Ziemons <ben@rs485.network>

RUN apk add --no-cache uwsgi-python3 python3 py3-yaml py3-pip py3-setuptools py3-matrix-nio py3-dateutil && \
    pip install -U pip && \
    pip install -U setuptools && \
    pip install -U Flask[async]

# copy required source files
COPY wmn/ /usr/local/lib/wmn/wmn

ARG WMN_UID=1000
ARG WMN_GID=1000

RUN mkdir -p /etc/wmn && \
    chmod 0700 /etc/wmn && \
    chown "${WMN_UID}" /etc/wmn && \
    addgroup -g "${WMN_GID}" wmn && \
    adduser -s /bin/sh -u "${WMN_UID}" -G wmn -D wmn

USER wmn
VOLUME /etc/wmn/config.yml
ENV WMN_CONFIG_PATH=/etc/wmn/config.yml

ARG PORT=3031
EXPOSE $PORT
ENV UWSGI_SOCKET=:$PORT

# opens a uwsgi socket at the given port, which is to be used by a reverse proxy
CMD [ "uwsgi", "--die-on-term", \
               "--need-plugin", "python3", \
               "--module", "wmn.wmn", \
               "--pythonpath", "/usr/local/lib/wmn", \
               "--master", \
               "--processes", "1", \
               "--threads", "2" ]
