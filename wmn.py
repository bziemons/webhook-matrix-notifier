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

        def sort_commits_by_time(commits):
            return sorted(commits, key=lambda commit: commit["timestamp"])

        def extract_commit_message(commit):
            return next(commit["message"].splitlines(keepends=False), "$EMPTY_COMMIT_MESSAGE - impossibruh").strip()

        username = request.json["user_name"]
        commit_messages = list(map(extract_commit_message, sort_commits_by_time(request.json["commits"])))
        project_name = request.json["project"]["name"]
        html_commits = "\n".join((f"  <li>{msg}</li>" for msg in commit_messages))
        text_commits = "\n".join((f"- {msg}" for msg in commit_messages))
        room.send_html(f"<strong>{username} pushed {len(commit_messages)} commits to {project_name}</strong><br>\n"
                       f"<ul>\n{html_commits}\n</ul>\n",
                       body=f"{username} pushed {len(commit_messages)} commits to {project_name}\n{text_commits}\n",
                       msgtype="m.notice")

    return ""
