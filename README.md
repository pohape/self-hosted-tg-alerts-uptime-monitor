## 🛡️ Self-hosted Website Uptime Monitor with Telegram Alerts on errors

💬 Monitor your websites using **GET/POST/HEAD** requests, verify **SSL certificates**, check for **specific content**, and watch **domain registration expiry** — all configured via a simple YAML file.  
Get instant **Telegram alerts** after N failures and a recovery notification when the site is back online.  
**No cloud. No lock-in. No Docker. Just Python + crontab.**

---

### 🏠 Why Self-Hosted?

- ✅ Runs anywhere — no Docker or containers needed
- ✅ No third-party APIs or subscriptions
- ✅ Full control, full privacy

---

### 🔧 Perfect for:

- Internal tools & dashboards
- APIs that shouldn’t go unnoticed
- Low-cost uptime monitoring (no external services)

---

### 🚀 Features

- 🔁 **HTTP Methods**: GET, POST, HEAD
- 🔐 **SSL Certificate Expiry Checks**
- 🌐 **Domain Registration Expiry Checks**: RDAP for most TLDs, whois for .ru / .рф / .su and regional zones like spb.ru; IDN domains welcome
- 🧠 **Content Validation**:
     * ✅ search_string: Verify a specific string is present in the response
     * ❌ absent_string: Verify a specific string is absent in the response
- 🧾 **Response Header Validation**:
     * ✅ response_headers contains: Verify a response header contains a specific substring
     * ❌ response_headers absent: Verify a response header does not contain a specific substring
- 🛠️ **Custom Headers** & POST data
- 🕒 **Flexible Cron Scheduling** per check, with automatic once-a-minute re-checks while something is down
- 💬 **Telegram Alerts** on errors & recovery
- 📊 **Summary Reports**: one consolidated scheduled Telegram report of all services that are still down
- ⚙️ **YAML-Based Config** — easy to read, edit, and version
- 🖥️ **Shell Command Monitoring**: Run any command and validate its output
- 🧪 **Debug/Test Modes** to simplify setup

---

### ⚡ Quick Start
Spin up your own uptime monitor with Telegram alerts in just a few steps:
#### 🔧 1. Clone the repo & install dependencies
```shell
git clone https://github.com/pohape/self-hosted-tg-alerts-uptime-monitor
cd self-hosted-tg-alerts-uptime-monitor
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```
![Step 1](https://raw.githubusercontent.com/pohape/self-hosted-tg-alerts-uptime-monitor-assets/main/step1.gif)

#### 🤖 2. Create a Telegram bot
Chat with [@BotFather](https://t.me/BotFather), create a new bot, and copy the token.
![Step 2](https://raw.githubusercontent.com/pohape/self-hosted-tg-alerts-uptime-monitor-assets/main/step2.gif)

#### ✍️ 3. Create the config file
Initialize your config.yaml with your Telegram bot token:
```shell
echo "telegram_bot_token: '12345:SDGFFHWRE-EW3b16Q'" > config.yaml
```
![Step 3](https://raw.githubusercontent.com/pohape/self-hosted-tg-alerts-uptime-monitor-assets/main/step3.gif)

#### 🆔 4. Get your Telegram chat ID
Start the bot in ID mode to find out your user/chat ID:
```shell
python3 run.py --id-bot-mode
```
➡️ Send any message to your bot, or forward a message from the group where you want to receive notifications.  
🛠️ If you want to receive notifications in a group, make sure the bot has been added to that group.
![Step 4](https://raw.githubusercontent.com/pohape/self-hosted-tg-alerts-uptime-monitor-assets/main/step4.gif)

#### ✍️ 5. Add a site to monitor
Edit **config.yaml** and define your site(s):

```yaml
telegram_bot_token: 'YOUR_BOT_TOKEN_HERE'

sites:
  homepage:
    url: "https://example.com"
    search_string: "Example Domain"
    tg_chats_to_notify:
      - '123456789'  # your Telegram user or chat ID
```
![Step 5](https://raw.githubusercontent.com/pohape/self-hosted-tg-alerts-uptime-monitor-assets/main/step5.gif)

#### 💯 6. Test your setup
This will validate the configuration for each site and display any issues:
```shell
python3 run.py --check-config
```
Make sure Telegram alerts work:
```shell
python3 run.py --test-notifications
```
You’ll get a test message in every listed chat — or a clear error if something’s wrong.
![Step 6](https://raw.githubusercontent.com/pohape/self-hosted-tg-alerts-uptime-monitor-assets/main/step6.gif)

#### 🚀 7. Run a manual check
Force a one-time check of all sites, commands and domains:
```shell
python3 run.py --force
```
Or just one of them: `python3 run.py --only homepage` (see [Usage](#usage)).
![Step 7](https://raw.githubusercontent.com/pohape/self-hosted-tg-alerts-uptime-monitor-assets/main/step7.gif)

#### 🕒 8. Add to crontab
Enter your crontab:
```shell
crontab -e
```
Then add this line (replace **/path/to/repo** with the actual path to your cloned project):
```shell
* * * * * /path/to/repo/venv/bin/python /path/to/repo/run.py
```
📅 The entry point runs every minute, but each healthy check runs according to its own schedule, defined in the **config.yaml** using cron syntax. Once a site or command fails, it is re-checked every minute until it recovers (a domain — at most once an hour), see [Schedule, retries and `notify_after_attempt`](#-schedule-retries-and-notify_after_attempt)
![Step 8](https://raw.githubusercontent.com/pohape/self-hosted-tg-alerts-uptime-monitor-assets/main/step8.gif)

#### ⏰ 9. Simulate downtime and recovery (optional)
![Step 9](https://raw.githubusercontent.com/pohape/self-hosted-tg-alerts-uptime-monitor-assets/main/step9.gif)

### Usage

#### To run the script normally, simply execute:

```shell
python3 run.py
```

#### To test Telegram notifications:

```shell
python3 run.py --test-notifications
```

#### To start the Telegram bot that replies with user IDs using long polling:

```shell
python3 run.py --id-bot-mode
```

#### To force check all sites, commands and domains immediately:

```shell
python3 run.py --force
```
Example results:
```diff
+ home_page completed successfully

- Expected status code [404], but got '200'
+ A message sent to 5487855 successfully.
```

#### To check only some checks immediately:

```shell
python3 run.py --only home_page
python3 run.py --only home_page --only backup_sync_check   # repeat the flag...
python3 run.py --only home_page,backup_sync_check,shop_domain  # ...or separate names with commas
```

`--only NAME` is `--force` for the named checks only. A name can be any site, command or
domain (names are unique across the three sections). Notes:

- It is a real run, not a dry run: it takes the same lock as the cron job, updates the same
  state file and goes through the same alerting logic. A failing check counts as one more
  failed attempt and **may send the DOWN alert** if that reaches `notify_after_attempt`;
  a check that recovers sends the "back online" message.
- The named checks run right now regardless of their schedule. For a failing domain the
  hourly retry limit is ignored too — you asked for the lookup explicitly.
- All other checks are skipped and their state is left untouched (no retries, no pending
  alerts for them); the summary report is not sent either — that stays the cron job's work.
- An unknown name is an error: the script lists the unknown and the known names and exits
  with code 2 without running anything.
- If the cron run of the same minute is still in progress, the script exits with
  "Another instance is already running" — just repeat the command a few seconds later.
- It cannot be combined with `--force`, `--check-config`, `--test-notifications` or `--id-bot-mode`.

#### To check the configuration for any issues:

```shell
python3 run.py --check-config
```
Example results:
```diff
@@ home_page @@
!  timeout: not found, default value is '5'
!  status_code: not found, default value is '200'
!  schedule: not found, default value is '* * * * *'
+  url: https://example.com/
+  tg_chats_to_notify: 5487855
+  notify_after_attempt: 3  # Notify only after 3 failed checks in a row
+  method: GET
+  search_string: ENGLISH

@@ not_found @@
-  schedule: invalid cron syntax: '2 * * * '
+  url: https://example.com/qwerty
+  tg_chats_to_notify: -1831467, 5487855
+  timeout: 5
+  method: HEAD
+  status_code: 404
```

### Configuration

The configuration is done through the **config.yaml** file. Below is an example configuration:

```yaml
# Your Telegram Bot Token
telegram_bot_token: 'YOUR_TELEGRAM_BOT_TOKEN'
timezone: 'Europe/Moscow'  # (optional) schedules and displayed times use the machine timezone if not set
summary_schedule: '0 17 * * *'  # (optional) daily summary at 17:00 if at least one site is down
telegram_proxy: 'socks5h://127.0.0.1:1080'  # (optional) proxy for Telegram API calls only

sites:
  # 1. GET request to the main page where we look for "<body>"
  #    - No timeout specified (default is 5 seconds)
  #    - No method specified (default is GET)
  main_page_check:
    url: "https://example.com/"
    follow_redirects: True # Redirects are not followed by default
    search_string: "<body>"
    absent_string: "Not Found"
    # Notifications will be sent to the frontend group
    tg_chats_to_notify:
      - '1234567890'  # frontend group ID
    # Schedule: every minute (default)

  # 2. Explicit GET request to a non-existent page, expecting 404 and "Not Found"
  not_found_page_check:
    url: "https://example.com/nonexistent-page"
    follow_redirects: False # Redirects are not followed by default, making this the same as the default behavior.
    method: "GET"
    status_code: 404
    search_string: "Not Found"
    timeout: 2  # 2 seconds timeout
    # Notifications will be sent to the backend group
    tg_chats_to_notify:
      - '2345678901'  # backend group ID
    # Schedule: every 5 minutes
    schedule: '*/5 * * * *'  # Every 5 minutes

  # 3. POST request to the API with authorization and Content-Type JSON, expecting status_code = 201
  api_post_check:
    url: "https://example.com/api/endpoint"
    method: "POST"
    headers:
      Content-Type: 'application/json'
      Authorization: 'Bearer YOUR_API_TOKEN'
    post_data: '{"key": "value"}'
    status_code: 201
    timeout: 3  # 3 seconds timeout
    # Notifications will be sent to the API group and to the backend group
    tg_chats_to_notify:
      - '3456789012'  # API group ID
      - '2345678901'  # Backend group ID
    # Schedule: every 15 minutes
    schedule: '*/15 * * * *'  # Every 15 minutes

  # 4. Sending a contact form through POST request, as browsers typically do by default
  feedback_form_submission:
    url: "https://example.com/contact"
    method: "POST"
    headers:
      Content-Type: 'application/x-www-form-urlencoded'
    post_data: "name=John+Doe&email=john.doe%40example.com&message=Hello+World"
    status_code: 200
    search_string: "Thank you for your message"
    timeout: 2  # 2 seconds timeout
    # Notifications will be sent to the frontend group
    tg_chats_to_notify:
      - '1234567890'  # frontend group ID
    # Schedule: every day at midnight
    schedule: '0 0 * * *'  # Every day at 00:00

  # 5. HEAD request to privacy_policy.pdf to check resource availability
  privacy_policy_check:
    url: "https://example.com/privacy_policy.pdf"
    method: "HEAD"
    # Notifications will be sent to the backend group
    tg_chats_to_notify:
      - '2345678901'  # backend group ID
    # Schedule: every hour
    schedule: '0 * * * *'  # Every hour at 00 minutes
    # No timeout specified (default is 5 seconds)

  # 6. Check that an admin area requires HTTP Basic Auth
  admin_login_challenge:
    url: "https://admin.example.com/"
    method: "HEAD"
    status_code: 401
    response_headers:
      - name: "WWW-Authenticate"
        contains: 'Basic realm="Admin"'
    schedule: '*/5 * * * *'  # Every 5 minutes
    tg_chats_to_notify:
      - '2345678901'  # backend group ID

  # 7. Monitor ChatGPT API balance availability (one check costs ~$0.000001275)
  chat_gpt_balance_check:
    url: "https://api.openai.com/v1/chat/completions"
    method: "POST"
    headers:
      Content-Type: 'application/json'
      Authorization: 'Bearer YOUR_OPENAI_API_KEY'
    post_data: '{"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "Ping"}], "max_tokens": 1}'
    status_code: 200
    search_string: 'prompt_tokens'
    schedule: '0 * * * *'  # Every hour at 00 minutes
    tg_chats_to_notify:
      - '2345678999'  # infrastructure manager ID
```

- **telegram_bot_token**: Your Telegram bot token obtained from @BotFather.
- **timezone** (optional, default is the machine timezone): IANA timezone name (e.g. `Europe/Moscow`) used for all `schedule` / `summary_schedule` expressions and for the times shown in reports. You only need it when the server clock is in a different timezone than the one you write your schedules in. An unknown value stops the script with an error; run `python3 run.py --check-config` to see the valid ones.
- **summary_schedule** (optional): Cron expression that defines when a consolidated downtime summary should be sent. A message is generated only if at least one monitored service is still failing at that moment.
- **telegram_api_host** (optional, default is `api.telegram.org`): Host of the Telegram Bot API, or a **list of hosts** tried in order. Point it to your own mirror (e.g. `api.example.com`) to bypass blocking without a tunnel; give it two mirrors on different machines so losing one of them does not silence the alerts. See [Bypassing Telegram Blocking](#-bypassing-telegram-blocking). Provide bare hostnames — scheme/trailing slash are ignored and HTTPS is always used.
- **sites**: A list of sites to monitor.
- **url**: The URL of the site to monitor.
- **follow_redirects**: (optional, default is False): Whether to follow HTTP redirects during the request.
- **method** (optional, default is GET): The HTTP method to use (GET, POST, HEAD).
- **headers** (optional): A dictionary of HTTP headers to include in the request. The alert shows a cURL command to replicate the request; in it the values of `Authorization`, `Proxy-Authorization`, `Cookie` and `X-Api-Key` are replaced with `<hidden>`, so credentials never reach the Telegram chat.
- **response_headers** (optional): A list of response header rules. Each rule must contain `name` and exactly one of `contains` or `absent`.
- **post_data** (optional): Only for the POST method.
- **status_code** (optional, default is 200): An expected HTTP status code.
- **search_string** (optional): String that must be present in the HTTP response body for the check to pass.
- **absent_string** (optional): String that must be absent in the HTTP response body for the check to pass. Useful for detecting unexpected errors or messages.
- **timeout** (optional, default is 5): The timeout for the request in seconds.
- **schedule** (optional, default is '* * * * *'): The cron-like schedule for checking the site while it is healthy. A failing site is re-checked every minute regardless of it, see below.
- **tg_chats_to_notify**: List of Telegram chat IDs to notify in case of an error.
- **notify_after_attempt** (optional, default is 1): Number of consecutive failed checks required before a Telegram alert is sent. Helps to reduce false alarms from temporary glitches. Retries run every minute, so this is roughly "minutes of downtime", not "schedule periods" — see below.

If both **search_string** and **absent_string** are specified, both conditions must be satisfied for the site check to be considered successful.

Response header rule format:

```yaml
response_headers:
  - name: "WWW-Authenticate"
    contains: 'Basic realm="Admin"'
  - name: "Server"
    absent: "nginx/1.18.0"
```

- **name**: Response header name. Matching is case-insensitive.
- **contains**: Passes only if the response header exists and contains the given substring.
- **absent**: Passes if the response header is missing, or if the given substring is not present in its value.

Header checks work for all HTTP methods, including `HEAD`.

### 🔁 Schedule, retries and `notify_after_attempt`

The `schedule` only decides when a **healthy** check runs. As soon as a check fails, it leaves
its schedule:

- a failing **site** or **command** is re-checked **every minute** (the cron cadence of
  `run.py`) until it passes again;
- a failing **domain** is re-checked **at most once an hour**, to stay polite to the registries;
- after recovery the check returns to its own schedule.

`notify_after_attempt` counts these consecutive failed checks. So it is the retries, not the
schedule, that decide how soon you hear about an outage. Example:

```yaml
sites:
  hourly_page:
    url: "https://example.com/"
    schedule: "3 * * * *"      # hourly, at minute 3
    notify_after_attempt: 10
    tg_chats_to_notify:
      - '1234567890'
```

Say the site goes down at 10:05. The 10:03 check has already passed, so the next scheduled
check at 11:03 is the first failed attempt. From then on the site is checked every minute:
11:04 is attempt 2, … 11:12 is attempt 10, and the alert goes out at 11:12. In other words the
alert comes about 10 minutes after the first failed check (the 10th check, 9 minutes after the
first one); the worst case from the start of the outage is ~1 hour until a scheduled check
catches it plus ~9 minutes of retries — **not** 10 hours.

For a domain the same setting means hours: `notify_after_attempt: 2` alerts on the second
failed lookup, about an hour after the first one.

A manual `--force` / `--only` run of a failing check is one more attempt as well.

### Shell Command Monitoring

In addition to HTTP checks, you can monitor the output of shell commands. Commands use the same alerting logic as sites (DOWN/RESTORE Telegram notifications, cron scheduling, retry on failure).

Add a `commands` section to your **config.yaml**:

```yaml
commands:
  # Check that a command outputs an expected string
  backup_sync_check:
    command: "/opt/backup/check_sync.sh --status"
    search_string: "True"
    schedule: '5 0 * * *'  # Daily at 00:05
    timeout: 30
    tg_chats_to_notify:
      - '1234567890'

  # Alert if a numeric output drops below a threshold
  disk_free_space:
    command: "df /data --output=avail -BM | tail -1 | tr -d ' M'"
    min_value: 1000  # alert if less than 1000 MB free
    schedule: '0 * * * *'
    tg_chats_to_notify:
      - '1234567890'

  # Check that a forbidden string is absent
  service_health:
    command: "systemctl is-active my-service"
    search_string: "active"
    absent_string: "inactive"
    schedule: '* * * * *'
    tg_chats_to_notify:
      - '1234567890'
```

Command configuration fields:

- **command**: The shell command to execute (required)
- **search_string** (optional): String that must be present in stdout
- **absent_string** (optional): String that must NOT be present in stdout
- **min_value** (optional): If set, stdout is parsed as an integer and an alert is triggered if the value is below this threshold
- **timeout** (optional, default is 30): Command timeout in seconds
- **schedule**, **tg_chats_to_notify**, **notify_after_attempt**: Same as for sites (a failing command is re-checked every minute too)

> **`command` and `tg_chats_to_notify` are required** (for sites: `url` and
> `tg_chats_to_notify`; for domains: `domain` and `tg_chats_to_notify`). A check missing one of them cannot run, and that is reported as a
> failure of the check itself — an alert is sent and the check shows up in the state file.
> If the missing field is `tg_chats_to_notify`, the alert goes to every chat mentioned
> anywhere in the config, so it always has somewhere to go. Use `--check-config` to see all
> missing and defaulted fields at once.

### 🌐 Domain Expiry Monitoring

An expired domain takes every site on it down at once — and "site is down" does not tell you
"pay the registrar". Domain checks watch the registration itself, natively, like the SSL check
does for certificates. Add a `domains` section to your **config.yaml**:

```yaml
domains:
  shop_domain:
    domain: example.com
    warn_days: 30            # alert when less than 30 days are left
    schedule: '0 9 * * *'    # once a day is plenty
    tg_chats_to_notify:
      - '1234567890'

  clinic_domain:
    domain: клиника-пример.рф  # IDN is fine, it is converted to punycode internally
    notify_after_attempt: 2    # one failed lookup is not worth an alert
    tg_chats_to_notify:
      - '1234567890'
```

An alert is sent when:

- less than **warn_days** days are left before the registration expires;
- the domain has already **expired** (the alert also shows the registry state and, for .ru/.рф/.su, the `free-date` when anyone else may register it);
- the registry says the domain is **not registered**, **not delegated**, or has a hold / redemption / pending-delete status;
- the lookup itself fails (timeout, rate limit, unparseable answer) — use `notify_after_attempt` to ride out a single hiccup.

Domain configuration fields:

- **domain**: The domain name, Unicode or punycode (required)
- **warn_days** (optional, default is 30): Alert when fewer days than this are left
- **schedule** (optional, default is `'0 9 * * *'`, daily at 09:00): When to look the domain up while it is fine; a failing lookup is retried hourly instead
- **timeout** (optional, default is 10): Lookup timeout in seconds
- **whois_server** (optional): Query this whois server instead of the automatic choice — for TLDs without RDAP
- **tg_chats_to_notify**, **notify_after_attempt**: Same as for sites, but with hourly retries each attempt is an hour apart

Names must be unique across `sites`, `commands` and `domains`; `--check-config` reports a clash,
an invalid domain, a non-positive `warn_days` and a bad cron expression, and shows which data
source each domain will use.

Where the data comes from (standard library and `requests` only, no extra dependencies):

| Domain | Source | Expiry field |
|---|---|---|
| `*.ru`, `*.su`, `*.рф` (second level) | whois `whois.tcinet.ru` (TCI registry) | `paid-till`, plus `state` and `free-date` |
| `*.org.ru`, `*.net.ru`, `*.pp.ru` | whois `whois.nic.net.ru` (MSK-IX) | `paid-till`, plus `state` and `free-date` |
| other third-level `.ru` / `.su` (`spb.ru`, `msk.ru`, `com.ru`, …) | whois `whois.flexireg.net` | `Registry Expiry Date` |
| everything else (`.com`, `.net`, `.org`, most gTLDs and many ccTLDs) | RDAP, server from the [IANA bootstrap](https://data.iana.org/rdap/dns.json) | `expiration` event |

Limits worth knowing:

- Each domain is looked up once per scheduled run, and a failing domain is retried at most once an hour (sites and commands retry every minute); only an explicit `--only` lookup ignores that limit. Registries rate-limit whois; daily checks stay far below any limit.
- The IANA bootstrap file is cached in `/tmp` for a day; if it cannot be refreshed, the stale copy is used.
- Some ccTLDs publish neither RDAP nor an expiry date in whois (e.g. `.de`). For a TLD missing from the IANA bootstrap the check fails with a message asking for `whois_server`; it works only if that server's answer contains `paid-till`, `Registry Expiry Date`, `Registrar Registration Expiration Date`, `Expiration Date` or `Expiry Date`.
- The expiry date is the registry's. Registrars often renew on the last day or suspend the domain a little before it, so keep `warn_days` comfortably large.
- `status.py` shows the expiry date and the days left for every domain check.

### 🔄 Smart Recovery Notifications

- 🚨 One alert after N consecutive failures (no spam or duplicate messages)
- 🔁 Continues checking once a minute during downtime (ignoring the original schedule temporarily); a failing domain check is repeated once an hour instead, to stay polite to the registries. See [Schedule, retries and `notify_after_attempt`](#-schedule-retries-and-notify_after_attempt)
- ✅ "Back online" message sent when site recovers, with:
  - Duration of downtime (in minutes)
  - Number of failed checks
- 📆 After recovery, monitoring returns to your custom schedule — fully automated.

### 📊 Automated Summary Reports

- 📅 **Scheduled Summaries**: Configure periodic summary reports using cron syntax
- 🎯 **Smart Filtering**: Summaries are only sent when there are actually failing services
- 📋 **Comprehensive Overview**: Shows all services currently down with error details and duration
- 📢 **Broadcast Delivery**: Sent to all unique chat IDs from your monitored sites, commands and domains

### 🚧 Bypassing Telegram Blocking

If the host cannot reach `api.telegram.org` directly (e.g. your ISP or country blocks it), there are **two independent ways** to deliver alerts anyway — pick whichever fits your setup:

1. **`telegram_proxy`** — route only Telegram API calls through a SOCKS5/HTTP proxy (typically an SSH tunnel to a foreign VPS). Nothing else changes; site/command checks stay direct. See [Telegram Proxy](#️-telegram-proxy-optional).
2. **`telegram_api_host`** — point the monitor at your own mirror of the Bot API instead of `api.telegram.org`. No tunnel or local proxy required. See [Telegram API mirror](#-telegram-api-mirror-via-reverse-proxy-optional).

> 🇷🇺 **Важно для пользователей из России:** доступ к `api.telegram.org` заблокирован РКН — без одного из этих вариантов мониторинг не сможет отправлять уведомления. Проверки самих сайтов/команд при этом не затрагиваются.

The mirror approach is often the simplest to operate: there is no tunnel to keep alive, and the connection from the monitoring host uses your own (unblocked) domain in the TLS SNI, so DPI that filters by the `api.telegram.org` SNI does not see it.

### 🛰️ Telegram Proxy (optional)

You can route **only Telegram API calls** through a proxy. Site/command checks are **not** affected.

> 🇷🇺 **Важно для пользователей из России:** доступ к `api.telegram.org` заблокирован РКН. Без `telegram_proxy` мониторинг не сможет отправлять уведомления. Рекомендуется поднять SSH-туннель до любого зарубежного VPS и использовать его как локальный SOCKS5-прокси (см. пример ниже).

Add an optional top-level `telegram_proxy` to `config.yaml`:

```yaml
telegram_proxy: 'socks5h://127.0.0.1:1080'
```

Supported schemes:

| Scheme | When to use |
|---|---|
| `http://host:port` | Plain HTTP proxy |
| `socks5://host:port` | SOCKS5 proxy, hostname resolved locally |
| `socks5h://host:port` | SOCKS5 proxy, hostname resolved on the **proxy side** — recommended when DNS for `api.telegram.org` is also filtered locally |

SOCKS support requires PySocks, already included via `requests[socks]` in `requirements.txt`.

**Example: set up a local SOCKS5 proxy via SSH tunnel**

On any box you control (including the monitoring host itself), start an SSH tunnel to a server outside the blocked region:

```bash
ssh -D 0.0.0.0:1080 -N user@your-server.example.com
```

For production use it under a systemd service with `autossh` so it reconnects automatically:

```ini
[Unit]
Description=AutoSSH SOCKS5 tunnel for Telegram API
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=your-user
ExecStart=/usr/bin/autossh -M 0 -N \
    -o ServerAliveInterval=30 \
    -o ServerAliveCountMax=3 \
    -o ExitOnForwardFailure=yes \
    -D 0.0.0.0:1080 user@your-server.example.com
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Then in `config.yaml`:

```yaml
telegram_proxy: 'socks5h://127.0.0.1:1080'
```

Done — `api.telegram.org` calls now exit from your foreign server, while site/command checks still run directly from the monitoring host.

### 🪞 Telegram API mirror via reverse proxy (optional)

Instead of a tunnel, you can run a tiny **reverse proxy on your own foreign VPS** that transparently forwards Bot API requests to `api.telegram.org`, and point the monitor at it via `telegram_api_host`. Because the monitoring host now talks to *your* domain over HTTPS, the TLS SNI on the wire is your domain — not `api.telegram.org` — so SNI-based DPI lets it through, and there is no local proxy/tunnel to keep running.

Pick a subdomain you control (here shown as `api.example.com`), give it an `A` record pointing to your VPS, and let the VPS web server obtain a valid certificate for it automatically. With [Caddy](https://caddyserver.com/) the whole proxy is a few lines:

```caddy
api.example.com {
	# Optional but recommended: only allow your monitoring host(s).
	@blocked not remote_ip <YOUR_MONITORING_HOST_IP>
	route {
		respond @blocked "Forbidden" 403
		reverse_proxy https://api.telegram.org {
			header_up Host api.telegram.org
		}
	}
}
```

What happens:

- Caddy gets a real Let's Encrypt certificate for `api.example.com` (issued from your VPS, outside the blocked region).
- The monitor connects to `https://api.example.com/bot<token>/...`; Caddy re-issues the request to the genuine `api.telegram.org` (correct upstream SNI + `Host`), and the bot-token path / `/file/...` downloads pass through unchanged.
- TLS terminates legitimately at your VPS, so the monitor needs no certificate tweaks.

> ⚠️ Without the `remote_ip` allowlist the endpoint is an **open relay** to Telegram — anyone who learns the hostname could route their own bot traffic through your server. Restrict it to your monitoring host's IP (or add basic auth).

Then in `config.yaml`:

```yaml
telegram_api_host: 'api.example.com'
```

Leave `telegram_proxy` unset when using this approach.

#### Two mirrors are better than one

`telegram_api_host` also accepts a **list**, and a call walks it until one host
answers:

```yaml
telegram_api_host:
  - 'api.example.com'
  - 'api2.example.com'
```

This matters most when the monitor watches the very machine its mirror runs on.
With a single host, the outage you most need to hear about — that machine going
down — is exactly the one that takes your alert channel with it. Put the second
mirror on a different machine, ideally in a different datacentre.

A host is skipped and the next one tried when the request fails at the
transport level, when the host answers 5xx, or when the body is not JSON — all
three describe a broken mirror (a dying reverse proxy answers 502 with an HTML
error page). A 4xx with a JSON body is an *answer* from Telegram itself
("wrong token", "chat not found"), so it is returned as-is instead of being
retried elsewhere. If every host fails, the error is raised rather than
swallowed: a notification channel that breaks quietly is worse than none.

### 💬 Contributing

Found a bug? Want a new feature? [Open an issue](https://github.com/pohape/self-hosted-tg-alerts-uptime-monitor/issues) or submit a PR!



