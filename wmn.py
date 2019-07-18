import yaml
from flask import Flask, request, abort
from matrix_client.client import MatrixClient

application = Flask(__name__)

"""
config.yml Example:

secret: "..."
matrix:
  server: matrix.org
  username: ...
  password: "..."
"""
with open("config.yml", 'r') as ymlfile:
    cfg = yaml.safe_load(ymlfile)


@application.route('/matrix', methods=['POST'])
def notify():
    channel = request.args.get('channel')
    if channel is None or len(channel) == 0:
        abort(401)
    print(f"[DEBUG] Channel: {channel}")
    gitlab_token = request.headers.get('X-Gitlab-Token')
    if gitlab_token is None or len(gitlab_token) == 0 or gitlab_token != cfg['secret']:
        abort(403)
    print("[DEBUG] Correct secret")

    server = cfg["matrix"]["server"]
    client = MatrixClient(server)
    client.login(username=cfg["matrix"]["username"], password=cfg["matrix"]["password"])
    print(f"[DEBUG] Connected to matrix server {server}")

    room = client.join_room(room_id_or_alias=channel)
    room.send_text("Hello!")
    print(f"[DEBUG] Sent text to channel {room}")

    return ""
