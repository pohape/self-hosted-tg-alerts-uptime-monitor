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
from filesystem_helper import save_cache, load_yaml_or_exit, load_cache, acquire_singleton_lock, release_singleton_lock

CONFIG_PATH = 'config.yaml'
MESSAGES_PATH = 'messages.yaml'
LOCK_PATH = '/tmp/self-hosted-tg-alert-sites-monitoring-tool.lock'
CACHE_PATH = '/tmp/self-hosted-tg-alert-sites-monitoring-tool.json'

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


def get_certificate_expiry_with_cache(hostname: str, port: int = 443, timeout: float = 5.0) -> dict:
    cache_key = f"{hostname}:{port}:{timeout}"

    if cache_key not in certificate_cache:
        certificate_cache[cache_key] = get_certificate_expiry(hostname, port, timeout)
    else:
        certificate_cache[cache_key]['time_taken'] = 0.0  # Indicate cached result with zero time taken

    return certificate_cache[cache_key]


def get_certificate_expiry(hostname: str, port: int = 443, timeout: float = 1.0) -> dict:
    start_time = time.time()
    connect_timeout = float(timeout)

    if connect_timeout > 1.0:
        connect_timeout = 1.0

    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    last_err = None

    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            addrs = socket.getaddrinfo(hostname, port, family, socket.SOCK_STREAM)
        except Exception as e:
            last_err = e

            continue

        for af, socktype, proto, _canon, sa in addrs:
            sock = None

            try:
                sock = socket.socket(af, socktype, proto)
                sock.settimeout(connect_timeout)
                sock.connect(sa)

                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()

                sock = None
                not_before = datetime.strptime(cert['notBefore'], "%b %d %H:%M:%S %Y GMT").replace(tzinfo=timezone.utc)
                not_after = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y GMT").replace(tzinfo=timezone.utc)

                return {
                    'time_taken': round(time.time() - start_time, 2),
                    'issuer': cert.get('issuer'),
                    'not_before': not_before,
                    'not_after': not_after,
                    'is_valid': not_before <= datetime.now(tz=timezone.utc) <= not_after,
                    'error': None,
                }
            except Exception as e:
                last_err = e
            finally:
                # noinspection PyBroadException
                try:
                    if sock is not None:
                        sock.close()
                except Exception:
                    pass

    return {
        'time_taken': round(time.time() - start_time, 2),
        'issuer': None,
        'not_before': None,
        'not_after': None,
        'is_valid': None,
        'error': str(last_err) if last_err else "TLS precheck failed",
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
        cert = get_certificate_expiry_with_cache(hostname, parsed_url.port if parsed_url.port else 443, float(timeout))

        if cert['error']:
            return f"SSL certificate error: {cert['error']}"
        elif not cert['is_valid']:
            return f"SSL certificate has expired or is not yet valid: {cert['not_before']} - {cert['not_after']}"

        if cert['time_taken'] > 0:
            color_text(f"SSL check time for {hostname}: {cert['time_taken']} seconds", Color.QUOTATION)

    try:
        start_time = time.time()

        if method == RequestMethod.GET:
            res = requests.get(url, timeout=timeout, headers=headers, allow_redirects=follow_redirects)
        elif method == RequestMethod.POST:
            res = requests.post(url, timeout=timeout, headers=headers, allow_redirects=follow_redirects, data=post_data)
        elif method == RequestMethod.HEAD:
            res = requests.head(url, timeout=timeout, headers=headers, allow_redirects=follow_redirects)
        else:
            return 'Invalid request method.'

        elapsed_time = round(time.time() - start_time, 2)
        color_text(f"{method.value} request time for {url}: {elapsed_time} seconds", Color.QUOTATION)

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
        save_cache(CACHE_PATH, {})
    except Exception as e:
        color_text(f"Error saving cache, check permissions: {CACHE_PATH}\n{e}", Color.ERROR)

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

    # Check global summary_schedule parameter
    global_report = {
        Color.ERROR: {},
        Color.WARNING: {},
        Color.SUCCESS: {},
    }

    if 'summary_schedule' not in config:
        global_report[Color.WARNING]['summary_schedule'] = 'not found, summary reports will not be sent'
    else:
        summary_schedule = config['summary_schedule']
        if not is_valid_cron(summary_schedule):
            global_report[Color.ERROR]['summary_schedule'] = f"invalid cron syntax: '{summary_schedule}'"
        else:
            global_report[Color.SUCCESS]['summary_schedule'] = summary_schedule

    print_check_config_report(report, global_report)


def print_check_config_report(report, global_report=None):
    # Print global configuration first
    if global_report:
        color_text("\n=== GLOBAL CONFIGURATION ===", Color.TITLE)

        for color, field_info in global_report.items():
            for field_name, message in field_info.items():
                color_text(f"  {field_name}: {message}", color)

    # Print site-specific configuration
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
    parser.add_argument(
        '--test-notifications',
        action='store_true',
        help='Test sending messages to all Telegram chats found in the config file'
    )
    parser.add_argument(
        '--id-bot-mode',
        action='store_true',
        help='A bot that replies with the user ID using long polling'
    )
    parser.add_argument(
        '--force',
        action='store_true',
        help='Force check all sites immediately, regardless of the schedule'
    )
    parser.add_argument(
        '--check-config',
        action='store_true',
        help='Check configuration for each site and display missing or default values'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Debug mode'
    )

    args = parser.parse_args()

    if args.debug:
        color_text(f"[DEBUG] Parsed args: {args}", Color.QUOTATION)
        color_text(f"[DEBUG] Trying to acquire lock: {LOCK_PATH}", Color.QUOTATION)

    # noinspection PyUnusedLocal
    lock = acquire_singleton_lock(LOCK_PATH)

    if args.debug:
        color_text("[DEBUG] Lock acquired successfully", Color.SUCCESS)
        color_text(f"[DEBUG] Loading config from {CONFIG_PATH}", Color.QUOTATION)

    try:
        config = load_yaml_or_exit(CONFIG_PATH)

        if args.debug:
            color_text("[DEBUG] Config loaded successfully", Color.SUCCESS)

        if args.debug:
            color_text(f"[DEBUG] Loading messages from {MESSAGES_PATH}", Color.QUOTATION)

        messages = load_yaml_or_exit(MESSAGES_PATH)

        if args.debug:
            color_text("[DEBUG] Messages loaded successfully", Color.SUCCESS)

        if args.test_notifications:
            if args.debug:
                color_text("[DEBUG] Entering --test-notifications mode", Color.TITLE)

            telegram_helper.test_notifications(config, get_uniq_chat_ids)
            check_writing_to_cache()

            if args.debug:
                color_text("[DEBUG] Finished --test-notifications mode", Color.TITLE)

        elif args.id_bot_mode:
            if args.debug:
                color_text("[DEBUG] Entering --id-bot-mode", Color.TITLE)

            telegram_helper.id_bot(config)
            check_writing_to_cache()

            if args.debug:
                color_text("[DEBUG] Exiting --id-bot-mode (this usually runs until interrupted)", Color.TITLE)

        elif args.check_config:
            if args.debug:
                color_text("[DEBUG] Entering --check-config mode", Color.TITLE)

            check_config(config)
            check_writing_to_cache()

            if args.debug:
                color_text("[DEBUG] Finished --check-config mode", Color.TITLE)

        else:
            if args.debug:
                color_text("[DEBUG] Entering normal monitoring mode", Color.TITLE)

            cache = load_cache(CACHE_PATH)

            if args.debug:
                color_text(f"[DEBUG] Cache loaded from {CACHE_PATH}, entries={len(cache)}", Color.QUOTATION)

            process_each_site(args, config, cache, force=args.force)

            if args.debug:
                color_text(f"[DEBUG] process_each_site() finished", Color.QUOTATION)

            save_cache(CACHE_PATH, cache)

            if args.debug:
                color_text("[DEBUG] Cache saved after process_each_site()", Color.QUOTATION)

            process_cache(cache, config, messages)

            if args.debug:
                color_text("[DEBUG] process_cache() finished", Color.QUOTATION)

            send_summary_if_due(config, cache, messages)

            if args.debug:
                color_text("[DEBUG] send_summary_if_due() finished", Color.QUOTATION)

            save_cache(CACHE_PATH, cache)

            if args.debug:
                color_text("[DEBUG] Cache saved after send_summary_if_due()", Color.QUOTATION)

        if args.debug:
            color_text(
                f"[DEBUG] main() finished normally at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                Color.TITLE,
            )

    finally:
        if args.debug:
            color_text("[DEBUG] Releasing lock and exiting main()", Color.QUOTATION)

        release_singleton_lock()


def process_cache(cache, config, messages):
    for site_name, cache_info in cache.items():
        if site_name not in config['sites']:
            continue

        site = config['sites'][site_name]
        notify_after_attempt = site.get('notify_after_attempt', DEFAULT['notify_after_attempt'])

        failed_attempts = cache_info.get('failed_attempts', 0)
        notified_down = cache_info.get('notified_down', None)
        notified_restore = cache_info.get('notified_restore', None)
        last_error = cache_info.get('last_error')

        # Send initial DOWN alert once
        if failed_attempts >= notify_after_attempt and not notified_down and last_error is not None:
            tg_error_msg = generate_tg_error_msg(
                messages,
                last_error['msg'],
                site_name=last_error['site_name'],
                url=last_error['url'],
                follow_redirects=last_error['follow_redirects'],
                method=last_error['method'],
                timeout=last_error['timeout'],
                post_data=last_error['post_data'],
                headers=last_error['headers'],
                count=failed_attempts,
            )
            for chat_id in get_uniq_chat_ids(site['tg_chats_to_notify']):
                telegram_helper.send_message(config['telegram_bot_token'], chat_id, tg_error_msg)

            cache_info['notified_down'] = int(time.time())
            cache_info['notified_restore'] = None

        # Send RESTORE alert once
        elif last_error is None and notified_down and not notified_restore:
            msg = generate_back_online_msg(
                messages=messages,
                site_name=site_name,
                failed_attempts=cache_info.get('failed_attempts', 0),
                down_timestamp=notified_down,
            )
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
        color_text(f"{site_name} completed successfully\n", Color.SUCCESS)


def process_each_site(args, config, cache: dict, force=False) -> int:
    """
    Process all sites according to their schedules AND current error state.

    Behavior:
      - If force=True: check every site unconditionally.
      - Else:
          * If schedule matches now (should_run == True) -> check.
          * If the site currently has last_error in cache -> check
            on every run, regardless of schedule (DOWN/UNSTABLE retry).
          * Otherwise -> skip.

    Returns:
        int: number of sites that were actually processed.
    """
    sites = config.get('sites', {})

    if args.debug:
        color_text(
            f"[DEBUG] process_each_site(): total sites in config={len(sites)}, force={force}",
            Color.QUOTATION,
        )

    processed_count = 0
    skipped_count = 0

    for site_name, site in sites.items():
        schedule = site.get('schedule', DEFAULT['schedule'])
        cache_entry = cache.get(site_name, {})

        last_error = cache_entry.get('last_error')
        has_error = last_error not in (None, "", {})  # treat any non-empty last_error as a problem

        run_reason = None  # "force" | "schedule" | "down"

        if force:
            run_reason = "force"
        else:
            # Evaluate schedule
            run_by_schedule = False
            try:
                run_by_schedule = should_run(schedule)
            except Exception as e:
                if args.debug:
                    color_text(
                        f"[DEBUG] process_each_site(): ERROR evaluating schedule for '{site_name}' "
                        f"(schedule='{schedule}'): {e!r}",
                        Color.ERROR,
                    )

            # New behavior:
            # - If the site currently has an error -> we want to retry it every run.
            # - Otherwise fall back to schedule.
            if has_error:
                run_reason = "down"
            elif run_by_schedule:
                run_reason = "schedule"

        if run_reason is not None:
            if args.debug:
                color_text(
                    f"[DEBUG] process_each_site(): running '{site_name}' "
                    f"(reason={run_reason}, schedule='{schedule}', has_error={has_error})",
                    Color.QUOTATION,
                )

            process_site(site, site_name, cache)
            processed_count += 1
        else:
            skipped_count += 1

            if args.debug:
                color_text(
                    f"[DEBUG] process_each_site(): skipping '{site_name}' "
                    f"(schedule='{schedule}', has_error={has_error})",
                    Color.QUOTATION,
                )

    if args.debug:
        color_text(
            f"[DEBUG] process_each_site(): done, processed={processed_count}, skipped={skipped_count}",
            Color.QUOTATION,
        )

    return processed_count


def generate_summary_msg(messages: dict[str, str], cache: dict, config: dict) -> str:
    """Generate summary message with current services status"""
    services_down = []

    for site_name, cache_info in cache.items():
        if site_name not in config['sites']:
            continue

        site = config['sites'][site_name]
        notify_after_attempt = site.get('notify_after_attempt', DEFAULT['notify_after_attempt'])
        failed_attempts = cache_info.get('failed_attempts', 0)

        # Only include services that are actually down (failed attempts >= notify threshold)
        if failed_attempts >= notify_after_attempt and cache_info.get('last_error'):
            last_error = telegram_helper.escape_special_chars(cache_info['last_error']['msg'])
            notified_down_time = cache_info.get('notified_down')
            site_name_escaped = telegram_helper.escape_special_chars(site_name)

            if notified_down_time:
                minutes_down = round((int(time.time()) - notified_down_time) / 60)
                services_down.append(
                    f"🔴 _{site_name_escaped}_\n"
                    f"   Error: {last_error}\n"
                    f"   Down for: *{minutes_down}* minutes \\({failed_attempts} failed checks\\)"
                )

    if not services_down:
        services_down_text = "🟢 *All services are operational*"
    else:
        services_down_text = "\n\n".join(services_down)

    timestamp = telegram_helper.escape_special_chars(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    return messages['summary'].format(
        services_down=services_down_text,
        server_info=get_server_info(),
        timestamp=timestamp
    ).strip()


def should_send_summary(config: dict) -> bool:
    """Check if it's time to send summary based on summary_schedule"""
    if 'summary_schedule' not in config:
        return False

    schedule = config.get('summary_schedule', '')

    if schedule == '':
        return False
    elif not is_valid_cron(schedule):
        color_text(f"Invalid summary_schedule: '{schedule}'", Color.ERROR)

        return False

    base_time = datetime.now().replace(second=0, microsecond=0)

    try:
        cron = croniter(schedule, base_time)
        return cron.get_prev(datetime) == base_time or cron.get_next(datetime) == base_time
    except (CroniterBadCronError, CroniterBadDateError):
        return False


def send_summary_if_due(config, cache: dict, messages):
    """Send summary report if scheduled time has come and there are services down"""

    if not should_send_summary(config):
        return

    # Check if there are any services currently down
    has_services_down = False
    for site_name, cache_info in cache.items():
        if site_name not in config['sites']:
            continue

        site = config['sites'][site_name]
        notify_after_attempt = site.get('notify_after_attempt', DEFAULT['notify_after_attempt'])
        failed_attempts = cache_info.get('failed_attempts', 0)

        if failed_attempts >= notify_after_attempt and cache_info.get('last_error'):
            has_services_down = True
            break

    # Only send summary if there are services down
    if has_services_down:
        summary_msg = generate_summary_msg(messages, cache, config)

        # Collect all unique chat IDs from all sites
        all_chat_ids = set()
        for site in config['sites'].values():
            all_chat_ids.update(get_uniq_chat_ids(site['tg_chats_to_notify']))

        # Send summary to all chat IDs
        for chat_id in all_chat_ids:
            telegram_helper.send_message(config['telegram_bot_token'], chat_id, summary_msg)

        color_text("Summary report sent", Color.SUCCESS)


if __name__ == "__main__":
    main()
