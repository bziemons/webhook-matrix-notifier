import json
import re
from datetime import datetime

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


def get_msg_type():
    if 'msgtype' not in request.args:
        return "m.notice"
    msgtype = request.args.get('channel')
    if msgtype in ["m.text", "m.notice"]:
        return msgtype
    else:
        abort(400)


def iter_first_line(string: str):
    return iter(map(str.rstrip, string.lstrip().splitlines(keepends=False)))


def shorten(string: str, max_len: int = 80, appendix: str = "..."):
    if len(string) > max_len:
        return string[:max_len - len(appendix)] + appendix
    else:
        return string


def matrix_error(error: MatrixRequestError):
    # see Flask.make_response, this will be interpreted as (body, status)
    return f"Error from Matrix: {error.content}", error.code


def process_gitlab_request():
    check_token('X-Gitlab-Token')
    msgtype = get_msg_type()
    room = get_a_room()
    gitlab_event = request.headers.get("X-Gitlab-Event")

    if gitlab_event == "Push Hook":
        try:
            client = MatrixClient(cfg["matrix"]["server"])
            client.login(username=cfg["matrix"]["username"], password=cfg["matrix"]["password"])

            room = client.join_room(room_id_or_alias=room)
        except MatrixRequestError as e:
            return matrix_error(e)

        def sort_commits_by_time(commits):
            return sorted(commits, key=lambda commit: commit["timestamp"])

        def extract_commit_message(commit):
            return shorten(next(iter_first_line(commit["message"]), "$EMPTY_COMMIT_MESSAGE - impossibruh"))

        username = request.json["user_name"]
        commit_messages = list(map(extract_commit_message, sort_commits_by_time(request.json["commits"])))
        project_name = request.json["project"]["name"]
        html_commits = "\n".join((f"  <li>{msg}</li>" for msg in commit_messages))
        text_commits = "\n".join((f"- {msg}" for msg in commit_messages))
        try:
            room.send_html(f"<strong>{username} pushed {len(commit_messages)} commits to {project_name}</strong><br>\n"
                           f"<ul>\n{html_commits}\n</ul>\n",
                           body=f"{username} pushed {len(commit_messages)} commits to {project_name}\n{text_commits}\n",
                           msgtype=msgtype)
        except MatrixRequestError as e:
            return matrix_error(e)

    # see Flask.make_response, this is interpreted as (body, status)
    return "", 204


def process_jenkins_request():
    check_token('X-Jenkins-Token')
    msgtype = get_msg_type()
    room = get_a_room()
    jenkins_event = request.headers.get("X-Jenkins-Event")

    if jenkins_event == "Post Build Hook":
        try:
            client = MatrixClient(cfg["matrix"]["server"])
            client.login(username=cfg["matrix"]["username"], password=cfg["matrix"]["password"])

            room = client.join_room(room_id_or_alias=room)
        except MatrixRequestError as e:
            return matrix_error(e)

        def extract_change_message(change):
            change_message = next(iter_first_line(change["message"]), "")
            if len(change_message) > 0:
                htimestamp = datetime.fromtimestamp(change['timestamp'] / 1000).strftime("%d. %b %y %H:%M")
                return f"{shorten(change_message)} " \
                    f"({shorten(change['commitId'], 7, appendix='')}) " \
                    f"by {change['author']} " \
                    f"at {htimestamp}"
            else:
                return shorten(json.dumps(change), appendix="...}")

        build_name = request.json["displayName"]
        project_name = request.json["project"]["fullDisplayName"]
        result_type = request.json["result"]["type"]
        result_color = request.json["result"]["color"]
        change_messages = list(map(extract_change_message, request.json["changes"]))
        html_changes = "\n".join((f"  <li>{msg}</li>" for msg in change_messages))
        text_changes = "\n".join((f"- {msg}" for msg in change_messages))
        try:
            room.send_html(f"<p><strong>Build {build_name} on project {project_name} complete: "
                           f"<font color=\"{result_color}\">{result_type}</font></strong>, "
                           f"{len(change_messages)} commits</p>\n"
                           "" + (f"<ul>\n{html_changes}\n</ul>\n" if len(change_messages) > 0 else ""),
                           body=f"**Build {build_name} on project {project_name} complete: {result_type}**, "
                           f"{len(change_messages)} commits\n"
                           "" + (f"{text_changes}\n" if len(change_messages) > 0 else ""),
                           msgtype=msgtype)
        except MatrixRequestError as e:
            return matrix_error(e)

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
