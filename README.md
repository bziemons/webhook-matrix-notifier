# Webhook Matrix Notifier

Takes notifications via webhook, checks a secret and notifies a
[Matrix](https://matrix.org) channel. Listens to HTTP only. Should be used
behind a reverse-proxy with HTTPS.

# Testing the Hook locally
- Start the webserver locally by `env FLASK_APP=wmn.py flask run`
  - Or have your IDE do it for you
- Send a POST request using curl `curl -i -X POST "localhost:5000/matrix?channel=%21yhEUnvhAZZFKRStdXb%3Amatrix.org" -H "X-Gitlab-Event: Push Hook" -H "X-Gitlab-Token: ..." -H "Content-Type: application/json" --data-binary @./testrequest.json`
  - The part after `channel=` is the room ID which can retrieved from Matrix channels you are part of
  - `%21` escapes ! in HTML
  - `%3A` escapes : in HTML
  - The `X-Gitlab-Token` must correspond to the one provided in `config.yaml`
 
