# Copyright 2021 Benedikt Ziemons
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

import sys
from typing import Optional, Dict, Any, Tuple

import nio
import yaml

Cfg = Dict[str, Any]
ErrorResponseTuple = Tuple[str, int]


def format_response(error: "nio.ErrorResponse") -> ErrorResponseTuple:
    """
    :returns: tuple to be interpreted as (body, status), see Flask.make_response
    :rtype: ErrorResponseTuple
    """
    print("matrix_error was called with", error, file=sys.stderr, flush=True)
    if error.status_code:
        status = int(error.status_code)
    else:
        status = 500
    return f"Error from Matrix: {error.message}", status


class MatrixException(Exception):
    def __init__(self, response: "nio.ErrorResponse"):
        super(MatrixException, self).__init__("Error from Matrix: " + response.message)
        self.response = response

    def format_response(self) -> ErrorResponseTuple:
        return format_response(self.response)


def load_configuration() -> Cfg:
    with open("config.yml", "r") as ymlfile:
        return yaml.safe_load(ymlfile)


def save_configuration(configuration: Cfg):
    with open("config.yml", "w") as ymlfile:
        yaml.safe_dump(configuration, ymlfile)


async def client_login(configuration: Cfg) -> nio.AsyncClient:
    """
    :exception MatrixException: if the matrix server returns an error.
    :param configuration: the configuration object to load login data from.
    :type configuration: Cfg
    :return: the matrix client.
    :rtype: nio.AsyncClient
    """
    client = nio.AsyncClient(
        homeserver=configuration["matrix"].get("server"),
        user=configuration["matrix"].get("username", ""),
        device_id=configuration["matrix"].get("device_id", ""),
        store_path=configuration["matrix"].get("store_path", ""),
    )
    response = await client.login(
        password=configuration["matrix"].get("password", None),
        device_name=configuration["matrix"].get("device_name", ""),
        token=configuration["matrix"].get("token", None),
    )
    if isinstance(response, nio.ErrorResponse):
        raise MatrixException(response)

    if "device_id" not in configuration["matrix"]:
        configuration["matrix"]["device_id"] = response.device_id
        save_configuration(configuration)
    return client


async def send_message(
    client: nio.AsyncClient,
    room_id: str,
    text: str,
    msgtype: str = "m.text",
    html: Optional[str] = None,
) -> nio.RoomSendResponse:
    """
    :exception MatrixException: if the matrix server returns an error.
    :param client: the client to operate on.
    :param room_id: the room to send the message to.
    :param text: the text to send.
    :param msgtype: the message type to use. By default this is "m.text".
    :param html: optional html string to send with the message.
    :return: a room send response, which is never an nio.ErrorResponse.
    :rtype: nio.RoomSendResponse
    """
    content = {
        "body": text,
        "msgtype": msgtype,
    }
    if html is not None:
        content["format"] = "org.matrix.custom.html"
        content["formatted_body"] = html
    response = await client.room_send(
        room_id=room_id,
        message_type="m.room.message",
        content=content,
        ignore_unverified_devices=True,
    )
    if isinstance(response, nio.ErrorResponse):
        raise MatrixException(response)
    return response


async def resolve_room(client: nio.AsyncClient, room: str) -> str:
    """
    Takes a room alias or room id and always returns a resolved room id.
    :exception MatrixException: if the matrix server returns an error.
    :exception RuntimeError: if the passed room string cannot be handled.
    :param client: the client to operate on.
    :param room: the room to resolve.
    :returns: the room's matrix id, starting with a "!".
    :rtype: str
    """

    if room.startswith("#"):
        response = await client.room_resolve_alias(room_alias=room)
        if isinstance(response, nio.ErrorResponse):
            raise MatrixException(response)
        return response.room_id
    elif room.startswith("!"):
        return room
    else:
        raise RuntimeError(f"Room {room} could not be resolved")
