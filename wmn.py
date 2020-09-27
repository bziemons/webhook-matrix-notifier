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

app = Flask(__name__)
application = app

# Not going to care for specifics like the underscore.
# Generally match room alias or id [!#]anything:example.com with unicode support.
room_pattern = re.compile(r'^[!#]\w+:[\w\-.]+$')

# prometheus has to many sub-second digits in their timestamp,
# so we get rid of nanoseconds here
promtime_to_isotime_pattern = re.compile(r'([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(\.[0-9]{6})?(?:[0-9]{3})?(Z|[+-][0-9]{2}:[0-9]{2})')

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


def color_format_html(color_hex: str, text: str):
    return f'<font color="#{color_hex}">{text}</font>'


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

    if not request.json:
        abort(400)

    # written for version 4 of the alertmanager webhook JSON
    # https://prometheus.io/docs/alerting/configuration/#webhook_config

    def color_status_html(status: str, text: typing.Optional[str] = None):
        _status_colors = {"resolved": "34A91D", "firing": "EF2929"}
        if text is None:
            text = status
        return color_format_html(_status_colors.get(status, "FFFFFF"), text)

    def color_severity_html(severity: str, text: typing.Optional[str] = None):
        _severity_colors = {"warning": "EFAC29", "critical": "EF2929"}
        if text is None:
            text = severity
        return color_format_html(_severity_colors.get(severity, "FFFFFF"), text)

    def parse_promtime(date_string):
        match = promtime_to_isotime_pattern.match(date_string)
        if match is None:
            print('parse_promtime failed, because promtime', date_string, 'could not be parsed with pattern', promtime_to_isotime_pattern, file=sys.stderr, flush=True)
            abort(400)
        grps = list(filter(lambda x: x is not None, match.groups()))
        if grps[-1] == 'Z':
            grps[-1] = '+00:00'
        return datetime.fromisoformat(''.join(grps))

    def alert_title(status: str, alertname: str, generator_url: str):
        if alertname:
            alertname = " alert " + alertname

        if status:
            status_msg = status.upper() if status == "firing" else status.title()
            title = status_msg + alertname
            html_title = color_status_html(status, title)
        elif alertname:
            title = alertname
            html_title = title
        else:
            title = ""
            html_title = title

        if title:
            title = f"*{title}*"
            if generator_url:
                title = f"{title} {generator_url}"

        if html_title:
            html_title = f"<strong>{html_title}</strong>"
            if generator_url:
                html_title = f'<a href="{generator_url}">{html_title}</a>'

        return title, html_title

    def extract_alert_message(alert: typing.Dict[str, typing.Any]) -> typing.Tuple[str, str]:
        """Takes the alert object and returns (text, html) as a string tuple."""

        labels = alert.get("labels", {})
        severity = labels.get("severity", "")
        annotations = alert.get("annotations", {})
        description = annotations.get("description", "")
        if not description:
            description = annotations.get("summary", "")

        alert_daterange = []
        if "startsAt" in alert and alert["startsAt"] != '0001-01-01T00:00:00Z':
            alert_start = parse_promtime(alert["startsAt"]).strftime("%d. %b %y %H:%M %Z").rstrip()
            alert_daterange.append(f'started at {alert_start}')
        if "endsAt" in alert and alert["endsAt"] != '0001-01-01T00:00:00Z':
            alert_end = parse_promtime(alert["endsAt"]).strftime("%d. %b %y %H:%M %Z").rstrip()
            alert_daterange.append(f'ended at {alert_end}')
        alert_daterange = ", ".join(alert_daterange)

        title, html_title = alert_title(
            status=alert.get("status", ""),
            alertname=labels.get("alertname", ""),
            generator_url=alert.get("generatorURL", "")
        )
        if severity:
            html_severity = f"Severity: {color_severity_html(severity)}"
            severity = severity.upper() if severity == 'critical' else severity.title()
            severity = f"Severity: {severity}"
        else:
            html_severity = ""

        html_parts = [html_title, html_severity, description, alert_daterange]
        html_message = "</p>\n<p>".join(filter(bool, html_parts))
        html_message = f"<p>{html_message}</p>" if html_message else ""
        return (
            " \n".join(filter(bool, [title, severity, description, alert_daterange])),
            html_message
        )

    try:
        client = MatrixClient(cfg["matrix"]["server"])
        client.login(username=cfg["matrix"]["username"], password=cfg["matrix"]["password"])
        room = client.join_room(room_id_or_alias=room)
        try:
            for body, html in map(extract_alert_message, request.json.get("alerts", [])):
                if html and body:
                    room.send_html(html=html, body=body, msgtype=msgtype)
                elif body:
                    room.send_text(body)
        except (LookupError, ValueError, TypeError):
            room.send_text("Error parsing data in prometheus request")
            print("Error parsing JSON and forming message:", file=sys.stderr)
            traceback.print_exc()
            print(file=sys.stderr, flush=True)
            return "Error parsing JSON and forming message", 500
    except MatrixRequestError as e:
        return matrix_error(e)

    # see Flask.make_response, this is interpreted as (body, status)
    return "", 204


@app.route('/matrix', methods=("POST",))
def notify():
    if 'X-Gitlab-Token' in request.headers:
        return process_gitlab_request()
    elif 'X-Jenkins-Token' in request.headers:
        return process_jenkins_request()
    elif 'type' in request.args and request.args.get('type') == "prometheus":
        return process_prometheus_request()
    else:
        return "Cannot determine the request's webhook cause", 400
