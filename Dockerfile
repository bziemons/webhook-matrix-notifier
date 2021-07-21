FROM docker.io/alpine:latest
MAINTAINER Benedikt Ziemons <ben@rs485.network>

RUN apk add --no-cache uwsgi-python3 python3 py3-yaml py3-flask py3-matrix-nio py3-dateutil

# partly from https://hub.docker.com/_/python?tab=description#create-a-dockerfile-in-your-python-app-project
WORKDIR /usr/src/wmn

# copy required source file
COPY wmn.py ./

WORKDIR /run/wmn

ARG WMN_UID=999

# requires config.yml to be present at build
COPY config.yml ./
RUN chown -R $WMN_UID /run/wmn && chmod 0600 /run/wmn/config.yml

USER $WMN_UID

ARG PORT=3031
EXPOSE $PORT
ENV UWSGI_SOCKET=:$PORT

# opens a uwsgi socket at the given port, which is to be used by a reverse proxy
CMD [ "uwsgi", "--die-on-term", \
               "--need-plugin", "python3", \
               "--wsgi-file", "/usr/src/wmn/wmn.py", \
               "--master", \
               "--processes", "1", \
               "--threads", "2" ]
