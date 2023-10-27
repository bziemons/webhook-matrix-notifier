#!/usr/bin/env python3
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

import argparse
import asyncio
import logging
import re
import sys

import nio

from .common import (
    client_login,
    send_message,
    resolve_room,
    MatrixException,
    load_configuration,
)

# Not going to care for specifics like the underscore.
# Generally match !anything:example.com with unicode support.
room_pattern = re.compile(r"^!\w+:[\w\-.]+$")


async def main():
    """
    config.yml Example:

    matrix:
      server: https://matrix.org
      username: ...
      password: "..."
    """
    logging.basicConfig()
    cfg = load_configuration()

    parser = argparse.ArgumentParser(description="Notify a Matrix room.")
    parser.add_argument(
        "-c", "--channel", required=False, help="the channel to send the message to (deprecated, use --room)"
    )
    parser.add_argument(
        "-r", "--room", required=False, help="the Matrix room to send the message to"
    )
    parser.add_argument(
        "-t",
        "--type",
        required=False,
        help="the msgtype",
        choices=("m.text", "m.notice"),
        default="m.text",
    )
    parser.add_argument("text", help="the text message to send to the room")
    parser.add_argument(
        "html", nargs="?", help="the html message to send to the room"
    )
    args = parser.parse_args()

    if not args.channel and not args.room:
        logging.error("Specify the Matrix room to send the message to")
        sys.exit(1)
    if args.room:
        room = args.room
    else:
        room = args.channel

    if room_pattern.fullmatch(room) is None:
        logging.error("Could not parse Matrix room '%s'", room)
        sys.exit(1)

    client = await client_login(cfg)
    try:
        room_id = await resolve_room(client=client, room=room)
        response = await client.join(room_id=room_id)
        if isinstance(response, nio.ErrorResponse):
            raise MatrixException(response)

        if "html" in args:
            response = await send_message(
                client=client,
                room_id=room_id,
                text=(args.text or ""),
                msgtype=args.type,
                html=args.html,
            )
        else:
            response = await send_message(
                client=client, room_id=room_id, text=args.text, msgtype=args.type
            )
    finally:
        await client.close()
    logging.info("Message sent. %s", response.event_id)


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
