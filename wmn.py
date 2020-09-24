import json
import re
import sys
import traceback
import typing
from datetime import datetime

import yaml
from flask import Flask, request, abort
from matrix_client.client import MatrixClient
from matrix_client.errors import MatrixRequestError

application = Flask(__name__)

# Not going to care for specifics like the underscore.
# Generally match room alias or id [!#]anything:example.com with unicode support.
room_pattern = re.compile(r'^[!#]\w+:[\w\-.]+$')

# prometheus has to many sub-second digits in their timestamp,
# so we get rid of nanoseconds here
promtime_to_isotime_pattern = re.compile(r'([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{6})?)(?:[0-9]{3})?(Z|[+-][0-9]{2}:[0-9]{2})')

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
        print('check_token failed, because token did not match', file=sys.stderr, flush=True)
        abort(401)


def get_a_room():
    if 'channel' not in request.args:
        print('get_a_room failed, because channel was not in request args', file=sys.stderr, flush=True)
        abort(400)
    room = request.args.get('channel')
    # sanitize input
    if room_pattern.fullmatch(room) is None:
        print('get_a_room failed, because channel', room, 'did not match room pattern', room_pattern, file=sys.stderr, flush=True)
        abort(400)
    return room


def get_msg_type():
    if 'msgtype' not in request.args:
        return "m.notice"
    msgtype = request.args.get('msgtype')
    if msgtype in ["m.text", "m.notice"]:
        return msgtype
    else:
        print('get_msg_type failed, because msgtype', msgtype, 'is not known', file=sys.stderr, flush=True)
        abort(400)


def iter_first_line(string: str):
    return iter(map(str.rstrip, string.lstrip().splitlines(keepends=False)))


def shorten(string: str, max_len: int = 80, appendix: str = "..."):
    if len(string) > max_len:
        return string[:max_len - len(appendix)] + appendix
    else:
        return string


def matrix_error(error: MatrixRequestError):
    print('matrix_error was called with', error, file=sys.stderr)
    traceback.print_exception(MatrixRequestError, error, error.__traceback__)
    print(file=sys.stderr, flush=True)
    # see Flask.make_response, this will be interpreted as (body, status)
    return f"Error from Matrix: {error.content}", error.code


def process_gitlab_request():
    check_token('X-Gitlab-Token')
    msgtype = get_msg_type()
    room = get_a_room()
    gitlab_event = request.headers.get("X-Gitlab-Event")

    if gitlab_event == "Push Hook":
        if request.json["total_commits_count"] < 1:
            return "", 204

        try:
            client = MatrixClient(cfg["matrix"]["server"])
            client.login(username=cfg["matrix"]["username"], password=cfg["matrix"]["password"])

            room = client.join_room(room_id_or_alias=room)
        except MatrixRequestError as e:
            return matrix_error(e)

        def sort_commits_by_time(commits):
            return sorted(commits, key=lambda commit: commit["timestamp"])

        def extract_commit_info(commit):
            msg = shorten(next(iter_first_line(commit["message"]), "$EMPTY_COMMIT_MESSAGE - impossibruh"))
            url = commit["url"]
            return msg, url

        username = request.json["user_name"]
        project_name = request.json["project"]["name"]
        if request.json["ref"].startswith("refs/heads/"):
            to_str = f" to branch {request.json['ref'][len('refs/heads/'):]} on project {project_name}"
        else:
            to_str = f" to {project_name}"

        commit_messages = list(map(extract_commit_info, sort_commits_by_time(request.json["commits"])))
        html_commits = "\n".join((f'  <li><a href="{url}">{msg}</a></li>' for (msg, url) in commit_messages))
        text_commits = "\n".join((f"- [{msg}]({url})" for (msg, url) in commit_messages))
        try:
            room.send_html(f"<strong>{username} pushed {len(commit_messages)} commits{to_str}</strong><br>\n"
                           f"<ul>\n{html_commits}\n</ul>\n",
                           body=f"{username} pushed {len(commit_messages)} commits{to_str}\n{text_commits}\n",
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

        project_url = request.json["githubProjectUrl"]

        def extract_change_message(change):
            change_message = next(iter_first_line(change["message"]), "")
            if len(change_message) > 0:
                htimestamp = datetime.fromtimestamp(change['timestamp'] / 1000).strftime("%d. %b %y %H:%M")
                bare_commit_link = f"({shorten(change['commitId'], 7, appendix='')})"
                if project_url is not None and project_url:
                    commit_link = f"<a href=\"{project_url}commit/{change['commitId']}\">{bare_commit_link}</a>"
                else:
                    commit_link = bare_commit_link
                return (
                    f"- {shorten(change_message)} {bare_commit_link} by {change['author']} at {htimestamp}",
                    f"  <li>{shorten(change_message)} {commit_link} by {change['author']} at {htimestamp}</li>",
                )
            else:
                dump = shorten(json.dumps(change), appendix="...}")
                return (
                    dump,
                    dump.replace("<", "&lt;").replace(">", "&gt;")
                )

        build_name = request.json["displayName"]
        project_name = request.json["project"]["fullDisplayName"]
        result_type = request.json["result"]["type"]
        result_color = request.json["result"]["color"]
        changes = request.json['changes']
        if len(changes) > 0:
            text_change_messages, html_change_messages = zip(*map(extract_change_message, changes))
        else:
            text_change_messages, html_change_messages = (), ()  # it's an owl!

        newline = '\n'
        try:
            room.send_html(f"<p><strong>Build {build_name} on project {project_name} complete: "
                           f"<font color=\"{result_color}\">{result_type}</font></strong>, "
                           f"{len(changes)} commits</p>\n"
                           "" + (f"<ul>\n{newline.join(html_change_messages)}\n</ul>\n" if len(html_change_messages) > 0 else ""),
                           body=f"**Build {build_name} on project {project_name} complete: {result_type}**, "
                                f"{len(changes)} commits\n"
                                "" + (f"{newline.join(text_change_messages)}\n" if len(text_change_messages) > 0 else ""),
                           msgtype=msgtype)
        except MatrixRequestError as e:
            return matrix_error(e)

    # see Flask.make_response, this is interpreted as (body, status)
    return "", 204


def process_prometheus_request():
    secret = request.args.get('secret')
    if secret != cfg['secret']:
        print('check_token failed, because token did not match', file=sys.stderr, flush=True)
        abort(401)

    msgtype = get_msg_type()
    room = get_a_room()

    # written for version 4 of the alertmanager webhook JSON
    # https://prometheus.io/docs/alerting/configuration/#webhook_config

    def color_status_html(status: str, text: typing.Optional[str] = None):
        _status_colors = {"resolved": "34A91D", "firing": "EF2929"}
        if text is None:
            text = status
        if status in _status_colors:
            return f'<font color="#{_status_colors[status]}">{text}</font>'
        else:
            return text

    def parse_promtime(date_string):
        match = promtime_to_isotime_pattern.match(date_string)
        if match is None:
            print('parse_promtime failed, because promtime', date_string, 'could not be parsed with pattern', promtime_to_isotime_pattern, file=sys.stderr, flush=True)
            abort(400)
        grps = list(map(lambda x: x is not None, match.groups()))
        if grps[-1] == 'Z':
            grps[-1] = '+00:00'
        return datetime.fromisoformat(''.join(grps))

    def extract_alert_message(alert: typing.Dict[str, typing.Any]) -> typing.Tuple[str, str]:
        """Takes the alert object and returns (text, html) as a string tuple."""

        alert_status = alert.get("status", "None")
        alert_labels = str(alert.get("labels", None))
        alert_annotations = str(alert.get("annotations", None))
        alert_start = alert.get("startsAt", None)
        alert_end = alert.get("endsAt", None)
        alert_daterange = []
        if alert_start is not None and alert_end != '0001-01-01T00:00:00Z':
            alert_start = parse_promtime(alert_start).strftime("%d. %b %y %H:%M %Z").rstrip()
            alert_daterange.append(f'Started at {alert_start}')
        if alert_end is not None and alert_end != '0001-01-01T00:00:00Z':
            alert_end = parse_promtime(alert_end).strftime("%d. %b %y %H:%M %Z").rstrip()
            alert_daterange.append(f'Ended at {alert_end}')
        alert_daterange = "" if len(alert_daterange) == 0 else f'({", ".join(alert_daterange)})'
        alert_generator_url = alert.get("generatorURL", "None")

        return (
            f'[{alert_status}] Labels: {alert_labels}, Annotations: {alert_annotations} - {alert_daterange} | Generator: {alert_generator_url}',
            f'<strong>{color_status_html(alert_status)}</strong> Labels: {alert_labels}, Annotations: {alert_annotations} - {alert_daterange} | Generator: {alert_generator_url}',
        )

    def extract_prometheus_message() -> typing.Tuple[str, str]:
        """Dissects the request's JSON and returns (text, html) as a string tuple."""

        group_key = request.json.get("groupKey", "None")
        status = request.json.get("status", "None")
        receiver = request.json.get("receiver", "None")
        group_labels = str(request.json.get("groupLabels", None))
        common_labels = str(request.json.get("commonLabels", None))
        common_annotations = str(request.json.get("commonAnnotations", None))
        ext_url = request.json.get("externalURL", "None")
        alerts = request.json.get("alerts", [])  # type: typing.List[typing.Dict[str, typing.Any]]

        text_alerts, html_alerts = zip(*map(extract_alert_message, alerts))
        text_alerts = "\n" + "\n".join((f"- {msg}" for msg in text_alerts))
        html_alerts = "<br>\n<ul>\n" + "\n".join((f"  <li>{msg}</li>" for msg in html_alerts)) + "\n</ul>"

        return (
            f'*{status.title()} alert for group {group_key}*\n  Receiver: {receiver}\n  Labels: {group_labels} | {common_labels}\n  Annotations: {common_annotations}\n  External URL: {ext_url}\nAlerts:{text_alerts}',
            f'<strong>{color_status_html(status, f"{status.title()} alert for group {group_key}")}</strong><br>\n  <em>Receiver:</em> {receiver}<br>\n  <em>Labels:</em> {group_labels} | {common_labels}<br>\n  <em>Annotations:</em> {common_annotations}<br>\n  <em>External URL:</em> {ext_url}<br>\n<em>Alerts:</em>{html_alerts}',
        )

    try:
        html, body = extract_prometheus_message()
    except (LookupError, ValueError, TypeError):
        print("Error parsing JSON and forming message:", file=sys.stderr)
        traceback.print_exc()
        print(file=sys.stderr, flush=True)
        return "Error parsing JSON and forming message", 500

    try:
        client = MatrixClient(cfg["matrix"]["server"])
        client.login(username=cfg["matrix"]["username"], password=cfg["matrix"]["password"])
        room = client.join_room(room_id_or_alias=room)
        room.send_html(html=html, body=body, msgtype=msgtype)
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
    elif 'type' in request.args and request.args.get('type') == "prometheus":
        return process_prometheus_request()
    else:
        return "Cannot determine the request's webhook cause", 400
