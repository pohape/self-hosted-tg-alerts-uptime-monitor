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


DEFAULT_API_HOST = 'api.telegram.org'

# Без срока запрос к мёртвому зеркалу висит до победного, и запасной адрес не
# получает шанса: резервирование без таймаута — это резервирование на бумаге.
API_TIMEOUT_SEC = 15

# getUpdates держит долгий поллинг (``timeout`` в параметрах запроса), поэтому
# HTTP-срок обязан его пережить, иначе штатное ожидание выглядело бы отказом.
LONG_POLL_TIMEOUT_SEC = 120


def get_api_hosts(config: dict) -> list:
    """Return Bot API hosts in preference order, normalised and de-duplicated.

    ``telegram_api_host`` accepts EITHER a single host or a list of them:

        telegram_api_host: 'api-mirror.example.com'

        telegram_api_host:
          - 'api-mirror.example.com'
          - 'api-mirror2.example.com'

    A list is what makes the alert channel survive the loss of one mirror: if
    the first host cannot be reached, the next one is tried within the same
    call. That matters when the monitor watches the very machine its mirror
    runs on — with a single host, the outage you most need to hear about is
    exactly the one that silences you.

    Hosts are bare names; any scheme or trailing slash is stripped and HTTPS is
    always used. Empty entries are dropped, and an empty list falls back to the
    official host — an unreachable configuration is worse than the default.
    """
    raw = config.get('telegram_api_host', DEFAULT_API_HOST)
    values = raw if isinstance(raw, (list, tuple)) else [raw]
    hosts = []

    for value in values:
        host = str(value or '').strip()
        host = host.replace('https://', '').replace('http://', '').strip().strip('/')

        if host and host not in hosts:
            hosts.append(host)

    return hosts or [DEFAULT_API_HOST]


def get_api_base(config: dict) -> str:
    """Return the base URL of the PRIMARY Bot API host, without a trailing slash."""
    return f"https://{get_api_hosts(config)[0]}"


def hide_token(value, token: str) -> str:
    """Render `value` with the bot token masked out.

    The token travels in the URL PATH of every Bot API call, so anything that
    quotes a failed request — `requests` exception text above all — quotes the
    token with it. Those lines end up in cron mail, logs and terminal
    scrollback, where a token is a credential lying in the open.
    """
    text = str(value)

    return text.replace(token, '<token>') if token else text


def api_request(config: dict, method: str, path: str, **kwargs) -> dict:
    """Call the Bot API, walking the configured hosts until one answers.

    A host is considered DEAD, and the next one is tried, when the request
    fails at the transport level, when the host replies 5xx, or when the body
    is not JSON. All three describe a broken mirror: our own reverse proxy
    returns 502/HTML exactly while the machine behind it is dying.

    A 4xx with a JSON body is an ANSWER, not a failure — Telegram itself says
    "wrong token" or "chat not found" that way, and repeating the question at
    another mirror would only repeat the answer.

    When every host fails, the last error is raised: silence about a broken
    notification channel would defeat the purpose of the tool.
    """
    hosts = get_api_hosts(config)
    token = config['telegram_bot_token']
    kwargs.setdefault('timeout', API_TIMEOUT_SEC)
    kwargs.setdefault('proxies', get_proxies(config))
    last_error = None

    for host in hosts:
        url = f"https://{host}/bot{token}{path}"

        try:
            response = requests.request(method, url, **kwargs)

            if response.status_code >= 500:
                raise requests.RequestException(
                    f"{host} answered {response.status_code}")

            return response.json()
        except (requests.RequestException, ValueError) as error:
            last_error = error

            if host != hosts[-1]:
                color_text(f"Telegram API host {host} failed "
                           f"({hide_token(error, token)}); trying the next one",
                           Color.WARNING)

    raise last_error


def get_bot_link(config: dict) -> str:
    response = api_request(config, 'GET', '/getMe')

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
    data = {
        "chat_id": chat_id,
        "text": message,
        "parse_mode": "MarkdownV2"
    }

    response_parsed = api_request(
        config,
        'POST',
        '/sendMessage',
        headers={"Content-Type": "application/json"},
        data=json.dumps(data),
    )

    if response_parsed['ok']:
        color_text(f"A message sent to {chat_id} successfully.", Color.SUCCESS)

        return None
    else:
        color_text(f"Failed to send test message to {chat_id}: {response_parsed['description']}", Color.ERROR)

        return response_parsed['description']


def get_updates(config, offset=None):
    params = {'timeout': 100, 'offset': offset}

    return api_request(config, 'GET', '/getUpdates', params=params,
                       timeout=LONG_POLL_TIMEOUT_SEC)


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
