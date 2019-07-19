FROM alpine

RUN apk add --no-cache uwsgi-python3 python3

# partly from https://hub.docker.com/_/python?tab=description#create-a-dockerfile-in-your-python-app-project
WORKDIR /usr/src/wmn
COPY requirements.txt ./
RUN pip3 install --no-cache-dir -r requirements.txt

# copy required source files
COPY wmn.py ./

WORKDIR /run/wmn
# requires config.yml to be present at build
COPY config.yml ./
RUN chown -R 999 /run/wmn && chmod 0600 /run/wmn/config.yml

USER 999

# opens a uwsgi socket at port 3031, which is to be used by a reverse proxy
CMD [ "uwsgi", "--die-on-term", \
               "--need-plugin", "python3", \
               "--socket", "0.0.0.0:3031", \
               "--wsgi-file", "/usr/src/wmn/wmn.py", \
               "--master", \
               "--processes", "1", \
               "--threads", "2" ]
