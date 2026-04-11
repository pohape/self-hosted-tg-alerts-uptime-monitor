import json
import time

import requests

from console_helper import Color, color_text


def get_proxies(config: dict):
    """Return a dict for requests' ``proxies=`` kwarg or None.

    Reads the optional top-level ``telegram_proxy`` from config.
    Supports any scheme accepted by requests, for example:
        - ``http://host:port``
        - ``socks5://host:port``
        - ``socks5h://host:port``  (resolves hostnames on the proxy side — useful for DPI bypass)

    SOCKS schemes require ``requests[socks]`` (PySocks) to be installed.
    """
    proxy = config.get('telegram_proxy')
    if not proxy:
        return None
    return {'http': proxy, 'https': proxy}


def get_bot_link(config: dict) -> str:
    url = f"https://api.telegram.org/bot{config['telegram_bot_token']}/getMe"
    response = requests.get(url, proxies=get_proxies(config)).json()

    if response.get("ok") and "result" in response:
        username = response["result"].get("username")

        if username:
            return f"https://t.me/{username}"
    else:
        error_message = response.get("description", "Unknown error")
        color_text(f"TG API error: {error_message}", Color.ERROR)
        exit()

    return "Could not determine bot link"


def id_bot(config: dict):
    link = get_bot_link(config)
    color_text('➡️ Your bot link:', Color.QUOTATION)
    print('   ' + link)
    print()

    color_text('➡️ To get your personal ID:', Color.QUOTATION)
    color_text(f'   Send any message to your bot.', Color.SUCCESS)
    color_text('   You’ll receive your TG ID to use in `tg_chats_to_notify`.', Color.SUCCESS)
    print()
    color_text('➡️ To get a group or channel ID:', Color.QUOTATION)
    color_text('   1. Add your bot to the target group/channel.', Color.SUCCESS)
    color_text('   2. Forward *any* message from that group/channel to the bot.', Color.SUCCESS)
    color_text('   You’ll receive the group/channel ID to use in `tg_chats_to_notify`.', Color.SUCCESS)
    print()
    color_text('💡 Press Ctrl+C to stop the bot when done.', Color.WARNING)
    print()

    last_update_id = None

    while True:
        updates = get_updates(config, last_update_id)

        if not updates['ok']:
            color_text('Telegram error: ' + str(updates), Color.ERROR)
            exit()
        elif 'result' in updates and updates['result']:
            for update in updates['result']:
                message = update.get('message')

                if message:
                    handle_message(config, message)
                    last_update_id = update['update_id'] + 1
        time.sleep(0.1)


def test_notifications(config, get_uniq_chat_ids):
    # Collect all unique chat IDs
    chat_ids = set()

    for site in config['sites'].values():
        chat_ids.update(get_uniq_chat_ids(site['tg_chats_to_notify']))

    # Send test message to each chat
    test_message = escape_special_chars('This is a test message from the monitoring script.')

    for chat_id in chat_ids:
        send_message(config, chat_id, test_message)


def escape_special_chars(text):
    special_chars = [
        '\\',
        '_',
        '~',
        '`',
        '>',
        '<',
        '&',
        '#',
        '+',
        '-',
        '=',
        '|',
        '{',
        '}',
        '.',
        '!',
        '$',
        '@',
        '[',
        ']',
        '(',
        ')',
        '^',
    ]

    text = str(text)

    for special_char in special_chars:
        text = text.replace(special_char, '\\' + special_char)

    return text


def send_message(config, chat_id, message):
    url = 'https://api.telegram.org/bot{}/sendMessage'.format(config['telegram_bot_token'])

    data = {
        "chat_id": chat_id,
        "text": message,
        "parse_mode": "MarkdownV2"
    }

    response = requests.post(
        url,
        headers={"Content-Type": "application/json"},
        data=json.dumps(data),
        proxies=get_proxies(config),
    )

    response_parsed = response.json()

    if response_parsed['ok']:
        color_text(f"A message sent to {chat_id} successfully.", Color.SUCCESS)

        return None
    else:
        color_text(f"Failed to send test message to {chat_id}: {response_parsed['description']}", Color.ERROR)

        return response_parsed['description']


def get_updates(config, offset=None):
    params = {'timeout': 100, 'offset': offset}
    response = requests.get(
        f"https://api.telegram.org/bot{config['telegram_bot_token']}/getUpdates",
        params=params,
        proxies=get_proxies(config),
    )

    return response.json()


def handle_message(config, message):
    chat_id = message['chat']['id']

    if 'forward_from' in message:
        forwarded_user_id = message['forward_from']['id']
        response_text = f'The ID of the forwarded user is `{forwarded_user_id}`'
    elif 'forward_origin' in message:
        if message['forward_origin']['type'] == 'hidden_user':
            response_text = f'No can do: forwarded from a hidden user'
        else:
            forwarded_chat_id = message['forward_origin']['chat']['id']
            response_text = f'The ID of the forwarded chat is `{forwarded_chat_id}`'
    else:
        user_id = message['from']['id']
        response_text = f'Your user ID is `{user_id}`'

    send_message(config, chat_id, response_text)
