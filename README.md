# Webhook Matrix Notifier

Takes notifications via webhook, checks a secret and notifies a [Matrix](https://matrix.org) room.
Listens to HTTP only. Should be used behind a reverse-proxy with HTTPS.

An example configuration is at `config.yml.example` and the program always reads the configuration file `config.yml`.


## Testing the Hook locally

First, start the webserver locally by `env FLASK_APP=wmn.py flask run` or have your IDE start it for you. \
Then, send a POST request using curl.

### GitLab

```
export URLQUOTED_ROOM=`python3 -c 'from urllib.parse import quote_plus; print(quote_plus("#room:matrix.org"))'`
curl -i -X POST "http://localhost:5000/matrix?room=${URLQUOTED_ROOM}" -H "X-Gitlab-Event: Push Hook" -H "X-Gitlab-Token: 123" -H "Content-Type: application/json" --data-binary @./testrequest_gitlab.json
```

The `X-Gitlab-Token` must correspond to the secret provided in `config.yml`

### Prometheus

```
export URLQUOTED_ROOM=`python3 -c 'from urllib.parse import quote_plus; print(quote_plus("#room:matrix.org"))'`
export URLQUOTED_SECRET=`python3 -c 'from urllib.parse import quote_plus; print(quote_plus("123"))'`
curl -i -X POST "http://localhost:5000/matrix?type=prometheus&secret=${URLQUOTED_SECRET}&room=${URLQUOTED_ROOM}" -H "Content-Type: application/json" --data-binary @./testrequest_prometheus.json
```

The secret must be passed as a URI parameter here.
