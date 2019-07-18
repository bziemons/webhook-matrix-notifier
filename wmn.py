import yaml
from flask import Flask, request, abort
from matrix_client.client import MatrixClient

application = Flask(__name__)

"""
config.yml Example:

secret: "..."
matrix:
  server: https://matrix.org
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
    gitlab_token = request.headers.get('X-Gitlab-Token')
    if gitlab_token is None or len(gitlab_token) == 0 or gitlab_token != cfg['secret']:
        abort(403)
    gitlab_event = request.headers.get("X-Gitlab-Event")

    if gitlab_event == "Push Hook":
        client = MatrixClient(cfg["matrix"]["server"])
        client.login(username=cfg["matrix"]["username"], password=cfg["matrix"]["password"])

        room = client.join_room(room_id_or_alias=channel)

        username = request.json["user_name"]
        commit_count = len(request.json["commits"])
        project_name = request.json["project"]["name"]
        room.send_html(f"<strong>{username} pushed {commit_count} commits to {project_name}</strong><br>\n"
                       "<ul>\n" + "\n".join((f"{commit['message']}" for commit in request.json["commits"])) + "</ul>\n",
                       body=f"{username} pushed {commit_count} commits to {project_name}\n"
                       "" + "\n".join((f"- {commit['message']}" for commit in request.json["commits"])) + "\n",
                       msgtype="m.notice")

    return ""
