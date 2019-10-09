#!/usr/bin/env python3

import argparse
import re
import sys

import yaml
from matrix_client.client import MatrixClient

# Not going to care for specifics like the underscore.
# Generally match !anything:example.com with unicode support.
room_pattern = re.compile(r'^!\w+:[\w\-.]+$')


def send_message(cfg, args):
    client = MatrixClient(cfg["matrix"]["server"])
    client.login(username=cfg["matrix"]["username"], password=cfg["matrix"]["password"])
    room = client.join_room(room_id_or_alias=args.channel)

    if 'html' in args:
        body = None if len(args.text) == 0 else str(args.text)
        room.send_html(html=args.html, body=body, msgtype=args.type)
    else:
        room.client.api.send_message(room_id=room.room_id, text_content=args.text, msgtype=args.type)


def main():
    """
    config.yml Example:

    matrix:
      server: https://matrix.org
      username: ...
      password: "..."
    """
    with open("config.yml", 'r') as ymlfile:
        cfg = yaml.safe_load(ymlfile)

    parser = argparse.ArgumentParser(description='Notify a matrix channel.')
    parser.add_argument('-c', '--channel', required=True, help='the channel to send the message to')
    parser.add_argument('-t', '--type', required=False, help='the msgtype',
                        choices=('m.text', 'm.notice'), default='m.text')
    parser.add_argument('text', help='the text message to send to the channel')
    parser.add_argument('html', nargs='?', help='the html message to send to the channel')
    args = parser.parse_args()

    if room_pattern.fullmatch(args.channel) is None:
        print("ERROR: Couldn't parse channel as a matrix channel", file=sys.stderr)
        sys.exit(1)

    send_message(cfg, args)
    print("Message sent.", file=sys.stderr)


if __name__ == "__main__":
    main()
