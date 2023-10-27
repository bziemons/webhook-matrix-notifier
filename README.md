# Webhook Matrix Notifier

Takes notifications via webhook, checks a secret and notifies a [Matrix](https://matrix.org) room.
Listens to HTTP only. Should be used behind a reverse-proxy with HTTPS.


## Configuration

An example configuration is located at `config.yml.example`.
By default the file `config.yml` in the current working directory will be used as the configuration.
To specify a different configuration file, use the environment variable `WMN_CONFIG_PATH`.


## Running the command line notifier

To notify a room with a simple text message, ensure credentials are filled out in your configuration file and run

```
python -m wmn.notify -r '!room:matrix.org' "text" "html"
```

Installing the webhook-matrix-notifier will create the shorthand script "matrix-notify" for this.


## Testing the webhook application locally

First, start the webserver locally by `env FLASK_APP=wmn.py flask run` or have your IDE start it for you. \
Then, send a POST request using curl.

### GitLab

```
export URLQUOTED_ROOM=`python3 -c 'from urllib.parse import quote_plus; print(quote_plus("#room:matrix.org"))'`
curl -i -X POST "http://localhost:5000/matrix?room=${URLQUOTED_ROOM}" -H "X-Gitlab-Event: Push Hook" -H "X-Gitlab-Token: 123" -H "Content-Type: application/json" --data-binary @./testrequest_gitlab.json
```

The `X-Gitlab-Token` must correspond to the secret provided in the configuration.

### Prometheus

```
export URLQUOTED_ROOM=`python3 -c 'from urllib.parse import quote_plus; print(quote_plus("#room:matrix.org"))'`
export URLQUOTED_SECRET=`python3 -c 'from urllib.parse import quote_plus; print(quote_plus("123"))'`
curl -i -X POST "http://localhost:5000/matrix?type=prometheus&secret=${URLQUOTED_SECRET}&room=${URLQUOTED_ROOM}" -H "Content-Type: application/json" --data-binary @./testrequest_prometheus.json
```

The secret must be passed as a URI parameter.

