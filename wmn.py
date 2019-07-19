import re

import yaml
from flask import Flask, request, abort
from matrix_client.client import MatrixClient
from matrix_client.errors import MatrixRequestError

application = Flask(__name__)

# Not going to care for specifics like the underscore.
# Generally match !anything:example.com with unicode support.
room_pattern = re.compile(r'^!\w+:[\w\-.]+$')

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


def check_token(header_field: str):
    token = request.headers.get(header_field)
    if token != cfg['secret']:
        abort(401)


def get_a_room():
    if 'channel' not in request.args:
        abort(400)
    room = request.args.get('channel')
    # sanitize input
    if room_pattern.fullmatch(room) is None:
        abort(400)
    return room


def process_gitlab_request():
    check_token('X-Gitlab-Token')
    room = get_a_room()
    gitlab_event = request.headers.get("X-Gitlab-Event")

    if gitlab_event == "Push Hook":
        try:
            client = MatrixClient(cfg["matrix"]["server"])
            client.login(username=cfg["matrix"]["username"], password=cfg["matrix"]["password"])

            room = client.join_room(room_id_or_alias=room)
        except MatrixRequestError as e:
            # see Flask.make_response, this is interpreted as (body, status)
            return f"Error from Matrix: {e.content}", e.code

        def sort_commits_by_time(commits):
            return sorted(commits, key=lambda commit: commit["timestamp"])

        def extract_commit_message(commit):
            return next(iter(commit["message"].lstrip().splitlines(keepends=False)),
                        "$EMPTY_COMMIT_MESSAGE - impossibruh").rstrip()

        username = request.json["user_name"]
        commit_messages = list(map(extract_commit_message, sort_commits_by_time(request.json["commits"])))
        project_name = request.json["project"]["name"]
        html_commits = "\n".join((f"  <li>{msg}</li>" for msg in commit_messages))
        text_commits = "\n".join((f"- {msg}" for msg in commit_messages))
        room.send_html(f"<strong>{username} pushed {len(commit_messages)} commits to {project_name}</strong><br>\n"
                       f"<ul>\n{html_commits}\n</ul>\n",
                       body=f"{username} pushed {len(commit_messages)} commits to {project_name}\n{text_commits}\n",
                       msgtype="m.notice")

    # see Flask.make_response, this is interpreted as (body, status)
    return "", 204


def process_jenkins_request():
    check_token('X-Jenkins-Token')
    # room = get_a_room()

    from pprint import pprint
    pprint(request.json)

    # see Flask.make_response, this is interpreted as (body, status)
    return "", 204


@application.route('/matrix', methods=("POST",))
def notify():
    if 'X-Gitlab-Token' in request.headers:
        return process_gitlab_request()
    elif 'X-Jenkins-Token' in request.headers:
        return process_jenkins_request()
    else:
        return "Cannot determine the request's webhook cause", 400
