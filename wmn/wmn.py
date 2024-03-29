# Copyright 2019-2021 Benedikt Ziemons
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
# the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
# FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
# IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import json
import logging
import re
from datetime import datetime
from typing import Tuple, Optional, Dict, Any

import dateutil.parser
import nio
from flask import Flask, request, abort
from werkzeug.datastructures import MultiDict

from .common import (
    client_login,
    send_message,
    Cfg,
    resolve_room,
    format_response,
    load_configuration,
    MatrixException,
)

RequestArgs = MultiDict[str, str]

logging.basicConfig()

# application is the wsgi variable name
application = Flask(__name__)

# Not going to care for specifics like the underscore.
# Generally match room alias or id [!#]anything:example.com with unicode support.
room_pattern = re.compile(r"^[!#]\w+:[\w\-.]+$")


def check_token(configuration: Cfg, token: str):
    if token != configuration["secret"]:
        logging.warning("request denied (401): check_token failed, because token did not match")
        abort(401)


async def get_a_room(client: nio.AsyncClient, request_args: RequestArgs) -> str:
    """Takes a nio.AsyncClient and the request args to return a room id."""

    if "channel" not in request_args and "room" not in request_args:
        logging.warning("request denied (400): get_a_room failed, because room was not in request args")
        abort(400)
    room = request_args.get("channel", "")
    room = request_args.get("room", room)
    if not room:
        logging.warning("request denied (400): get_a_room failed, because room was empty")
        abort(400)

    # sanitize input
    if room_pattern.fullmatch(room) is None:
        logging.warning("request denied (400): get_a_room failed, because room '%s' did not match room pattern '%s'", room, room_pattern)
        abort(400)

    try:
        return await resolve_room(client=client, room=room)
    except MatrixException as error:
        abort(application.make_response(error.format_response()))


def get_msg_type(request_args: RequestArgs):
    if "msgtype" not in request_args:
        return "m.notice"
    msgtype = request_args.get("msgtype")
    if msgtype in ["m.text", "m.notice"]:
        return msgtype
    else:
        logging.warning("request denied (400): get_msg_type failed, because msgtype '%s' is not known", msgtype)
        abort(400)


def color_format_html(color_hex: str, text: str):
    return f'<font color="#{color_hex}">{text}</font>'


def iter_first_line(string: str):
    return iter(map(str.rstrip, string.lstrip().splitlines(keepends=False)))


def shorten(string: str, max_len: int = 80, appendix: str = "..."):
    if len(string) > max_len:
        return string[: max_len - len(appendix)] + appendix
    else:
        return string


async def process_gitlab_request():
    cfg = load_configuration()
    check_token(configuration=cfg, token=request.headers.get("X-Gitlab-Token"))
    gitlab_event = request.headers.get("X-Gitlab-Event")

    try:
        client = await client_login(cfg)
    except MatrixException as error:
        return error.format_response()

    try:
        room_id = await get_a_room(client, request.args)
        msgtype = get_msg_type(request_args=request.args)

        if gitlab_event == "Push Hook":
            if request.json["total_commits_count"] < 1:
                return "", 204

            response = await client.join(room_id=room_id)
            if isinstance(response, nio.ErrorResponse):
                return format_response(response)

            def sort_commits_by_time(commits):
                return sorted(commits, key=lambda commit: commit["timestamp"])

            def extract_commit_info(commit):
                msg = shorten(
                    next(
                        iter_first_line(commit["message"]),
                        "$EMPTY_COMMIT_MESSAGE - impossibruh",
                    )
                )
                url = commit["url"]
                return msg, url

            username = request.json["user_name"]
            project_name = request.json["project"]["name"]
            if request.json["ref"].startswith("refs/heads/"):
                to_str = f" to branch {request.json['ref'][len('refs/heads/'):]} on project {project_name}"
            else:
                to_str = f" to {project_name}"

            commit_messages = list(
                map(extract_commit_info, sort_commits_by_time(request.json["commits"]))
            )
            html_commits = "\n".join(
                (
                    f'  <li><a href="{url}">{msg}</a></li>'
                    for (msg, url) in commit_messages
                )
            )
            text_commits = "\n".join(
                (f"- [{msg}]({url})" for (msg, url) in commit_messages)
            )

            response = await client.room_send(
                room_id=room_id,
                message_type="m.room.message",
                content={
                    "msgtype": msgtype,
                    "format": "org.matrix.custom.html",
                    "formatted_body": f"<strong>{username} pushed {len(commit_messages)} commits{to_str}</strong><br>\n"
                    f"<ul>\n{html_commits}\n</ul>\n",
                    "body": f"{username} pushed {len(commit_messages)} commits{to_str}\n{text_commits}\n",
                },
                ignore_unverified_devices=True,
            )
            if isinstance(response, nio.ErrorResponse):
                return format_response(response)

    except MatrixException as error:
        abort(application.make_response(error.format_response()))
    finally:
        await client.close()

    # see Flask.make_response, this is interpreted as (body, status)
    return "", 204


async def process_jenkins_request():
    cfg = load_configuration()
    check_token(configuration=cfg, token=request.headers.get("X-Jenkins-Token"))
    msgtype = get_msg_type(request_args=request.args)

    try:
        client = await client_login(cfg)
    except MatrixException as error:
        return error.format_response()

    try:
        room_id = await get_a_room(client, request.args)
        jenkins_event = request.headers.get("X-Jenkins-Event")

        if jenkins_event == "Post Build Hook":
            project_url = request.json["githubProjectUrl"]

            def extract_change_message(change):
                change_message = next(iter_first_line(change["message"]), "")
                if len(change_message) > 0:
                    htimestamp = datetime.fromtimestamp(
                        change["timestamp"] / 1000
                    ).strftime("%d. %b %y %H:%M")
                    bare_commit_link = (
                        f"({shorten(change['commitId'], 7, appendix='')})"
                    )
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
                    return (dump, dump.replace("<", "&lt;").replace(">", "&gt;"))

            build_name = request.json["displayName"]
            project_name = request.json["project"]["fullDisplayName"]
            result_type = request.json["result"]["type"]
            result_color = request.json["result"]["color"]
            changes = request.json["changes"]
            if len(changes) > 0:
                text_change_messages, html_change_messages = zip(
                    *map(extract_change_message, changes)
                )
            else:
                text_change_messages, html_change_messages = (), ()  # it's an owl!

            newline = "\n"  # expressions inside f-strings cannot contain backslashes...
            html_changes = (
                f"<ul>\n{newline.join(html_change_messages)}\n</ul>\n"
                if len(html_change_messages) > 0
                else ""
            )
            text_changes = (
                f"{newline.join(text_change_messages)}\n"
                if len(text_change_messages) > 0
                else ""
            )
            await send_message(
                client=client,
                room_id=room_id,
                text=(
                    f"**Build {build_name} on project {project_name} complete: {result_type}**, "
                    f"{len(changes)} commits\n"
                    f"{text_changes}"
                ),
                msgtype=msgtype,
                html=(
                    f"<p><strong>Build {build_name} on project {project_name} complete: "
                    f'<font color="{result_color}">{result_type}</font></strong>, '
                    f"{len(changes)} commits</p>\n"
                    f"{html_changes}"
                ),
            )

    except MatrixException as error:
        abort(application.make_response(error.format_response()))
    finally:
        await client.close()

    # see Flask.make_response, this is interpreted as (body, status)
    return "", 204


async def process_prometheus_request():
    # written for version 4 of the alertmanager webhook JSON
    # https://prometheus.io/docs/alerting/configuration/#webhook_config

    def color_status_html(status: str, text: Optional[str] = None):
        _status_colors = {"resolved": "34A91D", "firing": "EF2929"}
        if text is None:
            text = status
        return color_format_html(_status_colors.get(status, "FFFFFF"), text)

    def color_severity_html(severity: str, text: Optional[str] = None):
        _severity_colors = {"warning": "EFAC29", "critical": "EF2929"}
        if text is None:
            text = severity
        return color_format_html(_severity_colors.get(severity, "FFFFFF"), text)

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

    def extract_alert_message(alert: Dict[str, Any]) -> Tuple[str, str]:
        """Takes the alert object and returns (text, html) as a string tuple."""

        labels = alert.get("labels", {})
        severity = labels.get("severity", "")
        annotations = alert.get("annotations", {})
        description = annotations.get("description", "")
        if not description:
            description = annotations.get("summary", "")

        alert_daterange = []
        if "startsAt" in alert and alert["startsAt"] != "0001-01-01T00:00:00Z":
            alert_start = (
                dateutil.parser.isoparse(alert["startsAt"])
                .strftime("%d. %b %y %H:%M %Z")
                .rstrip()
            )
            alert_daterange.append(f"started at {alert_start}")
        if "endsAt" in alert and alert["endsAt"] != "0001-01-01T00:00:00Z":
            alert_end = (
                dateutil.parser.isoparse(alert["endsAt"])
                .strftime("%d. %b %y %H:%M %Z")
                .rstrip()
            )
            alert_daterange.append(f"ended at {alert_end}")
        alert_daterange = ", ".join(alert_daterange)

        title, html_title = alert_title(
            status=alert.get("status", ""),
            alertname=labels.get("alertname", ""),
            generator_url=alert.get("generatorURL", ""),
        )
        if severity:
            html_severity = f"Severity: {color_severity_html(severity)}"
            severity = severity.upper() if severity == "critical" else severity.title()
            severity = f"Severity: {severity}"
        else:
            html_severity = ""

        html_parts = [html_title, html_severity, description, alert_daterange]
        html_message = "</p>\n<p>".join(filter(bool, html_parts))
        html_message = f"<p>{html_message}</p>" if html_message else ""
        return (
            " \n".join(filter(bool, [title, severity, description, alert_daterange])),
            html_message,
        )

    cfg = load_configuration()
    secret = request.args.get("secret")
    if secret != cfg["secret"]:
        logging.warning("check_token failed, because token did not match")
        abort(401)

    try:
        client = await client_login(cfg)
    except MatrixException as error:
        return error.format_response()

    try:
        msgtype = get_msg_type(request_args=request.args)
        room_id = await get_a_room(client=client, request_args=request.args)

        if not request.json:
            abort(400)

        try:
            for text, html in map(
                extract_alert_message, request.json.get("alerts", [])
            ):
                if html and text:
                    await send_message(
                        client=client,
                        room_id=room_id,
                        text=text,
                        msgtype=msgtype,
                        html=html,
                    )
                elif text:
                    await send_message(
                        client=client, room_id=room_id, text=text, msgtype=msgtype
                    )
        except (LookupError, ValueError, TypeError):
            await send_message(
                client=client,
                room_id=room_id,
                text="Error parsing data in prometheus request",
            )
            logging.exception("Error parsing JSON and forming message")
            return "Error parsing JSON and forming message", 500
    except MatrixException as error:
        abort(application.make_response(error.format_response()))
    finally:
        await client.close()

    # see Flask.make_response, this is interpreted as (text, status)
    return "", 204


@application.post("/matrix")
async def notify():
    if "X-Gitlab-Token" in request.headers:
        return await process_gitlab_request()
    elif "X-Jenkins-Token" in request.headers:
        return await process_jenkins_request()
    elif "type" in request.args and request.args.get("type") == "prometheus":
        return await process_prometheus_request()
    else:
        return "Cannot determine the request's webhook cause", 400
