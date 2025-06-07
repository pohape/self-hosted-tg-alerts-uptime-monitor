import argparse
import socket
import ssl
import time
from datetime import datetime, timezone
from enum import Enum
from typing import cast
from urllib.parse import urlparse

import requests
from croniter import croniter, CroniterBadCronError, CroniterBadDateError

import telegram_helper
from console_helper import Color, color_text
from filesystem_helper import save_cache, load_yaml_or_exit, load_cache, get_cache_path

CONFIG_FILE_NAME = 'config.yaml'
MESSAGES_FILE_NAME = 'messages.yaml'
REQUIRED_FIELDS = ['url', 'tg_chats_to_notify']
DEFAULT = {
    'timeout': 5,
    'schedule': '* * * * *',
    'method': 'GET',
    'status_code': 200,
    'post_data': None,
    'search_string': '',
    'absent_string': '',
    'headers': {},
    'follow_redirects': False,
    'notify_after_attempt': 1,
}


class RequestMethod(Enum):
    GET = 'GET'
    POST = 'POST'
    HEAD = 'HEAD'


certificate_cache = {}


def get_certificate_expiry_with_cache(hostname: str, port: int = 443) -> dict:
    cache_key = '{}:{}'.format(hostname, port)

    if cache_key not in certificate_cache:
        certificate_cache[cache_key] = get_certificate_expiry(hostname, port)

    return certificate_cache[cache_key]


def get_certificate_expiry(hostname: str, port: int = 443) -> dict:
    try:
        context = ssl.create_default_context()

        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        not_before = datetime.strptime(cert['notBefore'], "%b %d %H:%M:%S %Y GMT").replace(tzinfo=timezone.utc)
        not_after = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y GMT").replace(tzinfo=timezone.utc)

        return {
            'issuer': cert['issuer'],
            'not_before': not_before,
            'not_after': not_after,
            'is_valid': not_before <= datetime.now(tz=timezone.utc) <= not_after,
            'error': None
        }
    except Exception as e:
        return {
            'issuer': None,
            'not_before': None,
            'not_after': None,
            'is_valid': None,
            'error': str(e)
        }


def get_server_info():
    hostname = socket.gethostname()
    hostname_escaped = telegram_helper.escape_special_chars(hostname)

    return f"```SERVER\n{hostname_escaped} ({socket.gethostbyname(hostname)})```"


def generate_curl_command(url: str,
                          follow_redirects: bool,
                          method: str,
                          timeout: int,
                          post_data: str = None,
                          headers: dict = None):
    header_options = ' '.join([f"-H '{key}: {value}'" for key, value in headers.items()]) if headers else ''
    base = f"curl --max-time {timeout} -v{' ' + header_options if header_options else ''} '{url}'"

    if follow_redirects:
        base += ' -L'

    if method == RequestMethod.HEAD.value:
        return f"{base} --head"
    elif method == RequestMethod.POST.value and post_data:
        return f"{base} -X POST -d '{post_data}'"
    elif method != RequestMethod.GET.value:
        return f"{base} -X {method}"

    return base


def generate_back_online_msg(messages: dict[str, str],
                             site_name: str,
                             failed_attempts: int,
                             down_timestamp: int):
    return messages['back_online'].format(
        site_name=telegram_helper.escape_special_chars(site_name),
        failed_attempts=failed_attempts,
        minutes=round((int(time.time()) - down_timestamp) / 60),
        server_info=get_server_info()
    ).strip()


def generate_tg_error_msg(messages: dict[str, str],
                          err: str,
                          site_name: str,
                          url: str,
                          follow_redirects: bool,
                          method: str,
                          timeout: int,
                          count: int,
                          post_data: str = None,
                          headers: dict = None):
    return messages['error'].format(
        site_name=telegram_helper.escape_special_chars(site_name),
        error=telegram_helper.escape_special_chars(err),
        server_info=get_server_info(),
        count=count,
        curl=generate_curl_command(url, follow_redirects, method, timeout, post_data, headers)
    ).strip()


def perform_request(url: str,
                    follow_redirects: bool,
                    method: RequestMethod,
                    status_code: int,
                    search: str,
                    absent: str,
                    timeout: int,
                    post_data: str,
                    headers: dict):
    if url.startswith('https://'):
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        cert = get_certificate_expiry_with_cache(hostname, parsed_url.port if parsed_url.port else 443)

        if cert['error']:
            return f"SSL certificate error: {cert['error']}"
        elif not cert['is_valid']:
            return f"SSL certificate has expired or is not yet valid: {cert['not_before']} - {cert['not_after']}"

    try:
        if method == RequestMethod.GET:
            res = requests.get(url, timeout=timeout, headers=headers, allow_redirects=follow_redirects)
        elif method == RequestMethod.POST:
            res = requests.post(url, timeout=timeout, headers=headers, allow_redirects=follow_redirects, data=post_data)
        elif method == RequestMethod.HEAD:
            res = requests.head(url, timeout=timeout, headers=headers, allow_redirects=follow_redirects)
        else:
            return 'Invalid request method.'

        if res.status_code != status_code:
            return f"Expected status code '{status_code}', but got '{res.status_code}'"

        # Only for GET/POST: validate content
        if method in {RequestMethod.GET, RequestMethod.POST}:
            if search and search not in res.text:
                return f"The expected string '{search}' was not found in the response."
            if absent and absent in res.text:
                return f"The forbidden string '{absent}' was found in the response."

        return None

    except requests.exceptions.RequestException as e:
        return f'An error occurred: {e}'


def should_run(schedule: str) -> bool:
    base_time = datetime.now().replace(second=0, microsecond=0)
    cron = croniter(schedule, base_time)

    return cron.get_prev(datetime) == base_time or cron.get_next(datetime) == base_time


def check_chat_id_validity(chat_id):
    return isinstance(chat_id, int) or (isinstance(chat_id, str) and chat_id.lstrip('-').isdigit())


def get_uniq_chat_ids(chat_ids):
    return set(map(str, chat_ids))


def check_writing_to_cache():
    try:
        save_cache({})
    except Exception as e:
        color_text(f"Error saving cache, check permissions: {get_cache_path()}\n{e}", Color.ERROR)

        return False

    return True


def check_config(config):
    report = {}

    for site_name, site in config['sites'].items():
        report[site_name] = {
            Color.ERROR: {},
            Color.WARNING: {},
            Color.SUCCESS: {},
        }

        for field_name in REQUIRED_FIELDS:
            if field_name not in site:
                report[site_name][Color.ERROR][field_name] = 'required field not found, you need to add it'
            elif field_name == 'tg_chats_to_notify':
                chat_id_list = site[field_name]

                if not isinstance(chat_id_list, list):
                    report[site_name][Color.ERROR][field_name] = 'must be a list of at least one chat ID'
                elif not all(check_chat_id_validity(chat_id) for chat_id in chat_id_list) or not chat_id_list:
                    report[site_name][Color.ERROR][field_name] = 'chat IDs must contain only digits'
                else:
                    report[site_name][Color.SUCCESS][field_name] = ', '.join(get_uniq_chat_ids(chat_id_list))
            else:
                report[site_name][Color.SUCCESS][field_name] = site[field_name]
        for field_name in site:
            if field_name not in REQUIRED_FIELDS and field_name not in DEFAULT:
                report[site_name][Color.WARNING][field_name] = 'unknown field, ignored'

        for field_name in DEFAULT:
            if field_name == 'post_data':
                method_is_post = site['method'].upper() == RequestMethod.POST.value if 'method' in site else False
                post_data_specified = 'post_data' in site

                if method_is_post and post_data_specified:
                    report[site_name][Color.SUCCESS][field_name] = site[field_name]
                elif method_is_post and not post_data_specified:
                    report[site_name][Color.WARNING][field_name] = 'the method is POST, but no post_data specified, '
                    report[site_name][Color.WARNING][field_name] += 'are you sure this is what you want?'
                elif not method_is_post and post_data_specified:
                    report[site_name][Color.WARNING][field_name] = 'ignored because the method is not POST'
            elif field_name == 'headers':
                if field_name in site:
                    if isinstance(site[field_name], dict):
                        headers_str = ', '.join([f'{k}: {v}' for k, v in site[field_name].items()])
                        report[site_name][Color.SUCCESS][field_name] = headers_str
                    else:
                        report[site_name][Color.ERROR][field_name] = 'must be a dictionary of header key-value pairs'
                else:
                    report[site_name][Color.WARNING][field_name] = 'not found, default value is empty headers'
            elif field_name in site:
                if field_name == 'schedule' and not is_valid_cron(site['schedule']):
                    report[site_name][Color.ERROR][field_name] = f"invalid cron syntax: '{site['schedule']}'"
                elif field_name == 'method':
                    method_upper = site[field_name].upper()

                    if not any(method_upper == item.value for item in RequestMethod):
                        report[site_name][Color.ERROR][field_name] = f"invalid method syntax: '{method_upper}'"
                    else:
                        report[site_name][Color.SUCCESS][field_name] = method_upper
                else:
                    report[site_name][Color.SUCCESS][field_name] = site[field_name]
            else:
                report[site_name][Color.WARNING][field_name] = f"not found, default value is '{DEFAULT[field_name]}'"

    print_check_config_report(report)


def print_check_config_report(report):
    for site_name, fields in report.items():
        color_text(f"\n=== {site_name} ===", Color.TITLE)
        for color, field_info in fields.items():
            for field_name, message in field_info.items():
                color_text(f"  {field_name}: {message}", color)


def is_valid_cron(schedule: str) -> bool:
    try:
        croniter(schedule)

        return True
    except (CroniterBadCronError, CroniterBadDateError):
        return False


def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='Run site monitoring script.')
    parser.add_argument('--test-notifications',
                        action='store_true',
                        help='Test sending messages to all Telegram chats found in the config file')
    parser.add_argument('--id-bot-mode',
                        action='store_true',
                        help='A bot that replies with the user ID using long polling')
    parser.add_argument('--force',
                        action='store_true',
                        help='Force check all sites immediately, regardless of the schedule')
    parser.add_argument('--check-config',
                        action='store_true',
                        help='Check configuration for each site and display missing or default values')
    args = parser.parse_args()

    config = load_yaml_or_exit(CONFIG_FILE_NAME)
    messages = load_yaml_or_exit(MESSAGES_FILE_NAME)

    if args.test_notifications:
        telegram_helper.test_notifications(config, get_uniq_chat_ids)
        check_writing_to_cache()
    elif args.id_bot_mode:
        telegram_helper.id_bot(config)
        check_writing_to_cache()
    elif args.check_config:
        check_config(config)
        check_writing_to_cache()
    else:
        cache = load_cache()
        process_each_site(config, cache, force=args.force)
        save_cache(cache)
        process_cache(cache, config, messages)
        save_cache(cache)


def process_cache(cache, config, messages):
    for site_name, cache_info in cache.items():
        failed_attempts = cache_info['failed_attempts']

        if site_name not in config['sites']:
            continue

        site = config['sites'][site_name]
        notify_after_attempt = site.get('notify_after_attempt', DEFAULT['notify_after_attempt'])

        if failed_attempts > 0 and time.time() - cache_info['last_checked_at'] >= 59:
            process_site(site, site_name, cache)

        notified_down = cache_info.get('notified_down', None)
        notified_restore = cache_info.get('notified_restore', None)

        if failed_attempts >= notify_after_attempt and not notified_down and cache_info['last_error'] is not None:
            tg_error_msg = generate_tg_error_msg(messages,
                                                 cache_info['last_error']['msg'],
                                                 site_name=cache_info['last_error']['site_name'],
                                                 url=cache_info['last_error']['url'],
                                                 follow_redirects=cache_info['last_error']['follow_redirects'],
                                                 method=cache_info['last_error']['method'],
                                                 timeout=cache_info['last_error']['timeout'],
                                                 post_data=cache_info['last_error']['post_data'],
                                                 headers=cache_info['last_error']['headers'],
                                                 count=failed_attempts)

            for chat_id in get_uniq_chat_ids(site['tg_chats_to_notify']):
                telegram_helper.send_message(config['telegram_bot_token'], chat_id, tg_error_msg)

            cache_info['notified_down'] = int(time.time())
            cache_info['failed_attempts'] = failed_attempts
            cache_info['notified_restore'] = None
        elif cache_info['last_error'] is None and notified_down and not notified_restore:
            msg = generate_back_online_msg(messages=messages,
                                           site_name=site_name,
                                           failed_attempts=cache_info['failed_attempts'],
                                           down_timestamp=cache_info['notified_down'])

            for chat_id in get_uniq_chat_ids(site['tg_chats_to_notify']):
                telegram_helper.send_message(config['telegram_bot_token'], chat_id, msg)

            cache_info['notified_restore'] = int(time.time())
            cache_info['failed_attempts'] = 0


def process_site(site, site_name: str, cache: dict):
    method_raw = site.get('method', None)

    if method_raw:
        method = RequestMethod(method_raw.upper())
    elif site.get('post_data'):
        method = RequestMethod.POST
    else:
        method = RequestMethod.GET

    follow_redirects = site.get('follow_redirects', DEFAULT['follow_redirects'])
    timeout: int = cast(int, site.get('timeout', DEFAULT['timeout']))
    post_data: str | None = cast(str, site.get('post_data', DEFAULT['post_data']))
    headers = site.get('headers', DEFAULT['headers'])

    error_message = perform_request(
        url=site['url'],
        follow_redirects=follow_redirects,
        method=method,
        status_code=site.get('status_code', DEFAULT['status_code']),
        search=site.get('search_string', DEFAULT['search_string']),
        absent=site.get('absent_string', DEFAULT['absent_string']),
        timeout=timeout,
        post_data=post_data,
        headers=headers
    )

    if site_name not in cache:
        cache[site_name] = {
            'last_checked_at': int(time.time()),
            'last_error': '',
            'notified_down': None,
            'notified_restore': None,
            'failed_attempts': 0,
        }
    else:
        cache[site_name]['last_checked_at'] = int(time.time())

    color_text(site_name + ':', Color.QUOTATION)

    if error_message:
        if cache[site_name]['failed_attempts'] == 0:
            cache[site_name]['failed_attempts'] = 1
            cache[site_name]['notified_down'] = None
            cache[site_name]['notified_restore'] = None
        else:
            cache[site_name]['failed_attempts'] += 1

        cache[site_name]['last_error'] = {
            'msg': error_message,
            'site_name': site_name,
            'url': site['url'],
            'follow_redirects': follow_redirects,
            'method': method.value,
            'timeout': timeout,
            'post_data': post_data,
            'headers': headers
        }

        color_text(error_message, Color.ERROR)
    else:
        cache[site_name]['last_error'] = None
        color_text(f"Request completed successfully", Color.SUCCESS)


def process_each_site(config, cache: dict, force=False):
    for site_name, site in config['sites'].items():
        if force or should_run(site.get('schedule', DEFAULT['schedule'])):
            process_site(site, site_name, cache)


if __name__ == "__main__":
    main()
