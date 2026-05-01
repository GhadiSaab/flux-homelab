#!/usr/bin/env python3
import os
import time
import threading
import logging
from datetime import datetime, timezone

import requests

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger(__name__)

ALERTMANAGER_URL = os.environ.get(
    'ALERTMANAGER_URL',
    'http://kube-prometheus-stack-alertmanager.monitoring-ns.svc.cluster.local:9093',
)
HOLMES_URL = os.environ.get(
    'HOLMES_URL',
    'http://holmesgpt-holmes.holmesgpt.svc.cluster.local:80',
)
DISCORD_WEBHOOK_URL = os.environ['DISCORD_WEBHOOK_URL']
DISCORD_BOT_TOKEN = os.environ['DISCORD_BOT_TOKEN']
DISCORD_CHANNEL_ID = os.environ['DISCORD_CHANNEL_ID']
POLL_INTERVAL = int(os.environ.get('POLL_INTERVAL', '60'))
# How long to wait for a reaction before giving up (seconds)
REACTION_TIMEOUT = int(os.environ.get('REACTION_TIMEOUT', '300'))

IGNORED_ALERTS: set[str] = {
    name.strip()
    for name in os.environ.get('IGNORED_ALERTS', 'Watchdog,InfoInhibitor').split(',')
    if name.strip()
}

SEVERITY_COLORS = {
    'critical': 0xFF0000,
    'warning':  0xFF8C00,
    'info':     0x3498DB,
}
DEFAULT_COLOR = 0x3498DB

DISCORD_API = 'https://discord.com/api/v10'
BOT_HEADERS = {
    'Authorization': f'Bot {DISCORD_BOT_TOKEN}',
    'Content-Type': 'application/json',
}

REACT_YES = '✅'
REACT_NO  = '❌'

processed: set[str] = set()
last_firing: set[str] = set()


# ---------- Alertmanager ----------

def get_firing_alerts() -> list[dict]:
    resp = requests.get(
        f'{ALERTMANAGER_URL}/api/v2/alerts',
        params={'active': 'true', 'silenced': 'false', 'inhibited': 'false'},
        timeout=10,
    )
    resp.raise_for_status()
    return [a for a in resp.json() if a.get('status', {}).get('state') == 'active']


# ---------- HolmesGPT ----------

def call_holmesgpt(prompt: str, retries: int = 5, backoff: int = 60) -> str:
    last_exc: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            resp = requests.post(
                f'{HOLMES_URL}/api/chat',
                json={'ask': prompt},
                timeout=600,
            )
            resp.raise_for_status()
            return resp.json().get('analysis', 'No analysis returned.')
        except Exception as exc:
            last_exc = exc
            log.warning('HolmesGPT attempt %d/%d failed: %s', attempt, retries, exc)
            if attempt < retries:
                time.sleep(backoff * attempt)
    raise last_exc


def investigate(alert: dict) -> str:
    name = alert['labels'].get('alertname', 'Unknown')
    desc = (
        alert['annotations'].get('description')
        or alert['annotations'].get('summary')
        or 'No description provided'
    )
    return call_holmesgpt(
        f'Investigate this alert and provide root cause and suggested fix: {name} - {desc}'
    )


def remediate(alert: dict, analysis: str) -> str:
    name = alert['labels'].get('alertname', 'Unknown')
    return call_holmesgpt(
        f'You previously analyzed this alert: {name}\n\n'
        f'Your analysis was:\n{analysis}\n\n'
        f'Now use your kubectl and bash tools to implement the fix. '
        f'Apply the changes to the cluster and report exactly what you did and whether it succeeded.'
    )


# ---------- Discord bot API ----------

def bot_post(alert: dict, analysis: str) -> str:
    """Post the analysis embed via the bot and return the message ID."""
    name = alert['labels'].get('alertname', 'Unknown')
    severity = alert['labels'].get('severity', 'info').lower()
    color = SEVERITY_COLORS.get(severity, DEFAULT_COLOR)
    namespace = alert['labels'].get('namespace', '')
    summary = alert['annotations'].get('summary', '')

    lines = []
    if summary:
        lines.append(f'**Summary:** {summary}')
    if namespace:
        lines.append(f'**Namespace:** `{namespace}`')
    lines.append('')
    lines.append('**HolmesGPT Analysis:**')
    lines.append(analysis[:3500])
    lines.append('')
    lines.append(f'React with {REACT_YES} to let HolmesGPT attempt the fix, or {REACT_NO} to skip.')

    embed = {
        'title': f'\U0001f6a8 {name}',
        'description': '\n'.join(lines),
        'color': color,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'footer': {'text': f'Severity: {severity.upper()} • via HolmesGPT'},
    }

    resp = requests.post(
        f'{DISCORD_API}/channels/{DISCORD_CHANNEL_ID}/messages',
        headers=BOT_HEADERS,
        json={'embeds': [embed]},
        timeout=10,
    )
    resp.raise_for_status()
    msg_id = resp.json()['id']
    log.info('Posted Discord embed for alert: %s (msg_id=%s)', name, msg_id)
    return msg_id


def add_reactions(msg_id: str) -> None:
    for emoji in (REACT_YES, REACT_NO):
        requests.put(
            f'{DISCORD_API}/channels/{DISCORD_CHANNEL_ID}/messages/{msg_id}/reactions/{emoji}/@me',
            headers={k: v for k, v in BOT_HEADERS.items() if k != 'Content-Type'},
            timeout=10,
        )


def get_reactions(msg_id: str, emoji: str) -> list[dict]:
    resp = requests.get(
        f'{DISCORD_API}/channels/{DISCORD_CHANNEL_ID}/messages/{msg_id}/reactions/{emoji}',
        headers=BOT_HEADERS,
        timeout=10,
    )
    if resp.status_code == 200:
        return resp.json()
    return []


def bot_update(msg_id: str, content: str) -> None:
    """Post a follow-up reply to the original alert message."""
    requests.post(
        f'{DISCORD_API}/channels/{DISCORD_CHANNEL_ID}/messages',
        headers=BOT_HEADERS,
        json={'content': content, 'message_reference': {'message_id': msg_id}},
        timeout=10,
    )


def get_bot_user_id() -> str:
    resp = requests.get(f'{DISCORD_API}/users/@me', headers=BOT_HEADERS, timeout=10)
    resp.raise_for_status()
    return resp.json()['id']


BOT_USER_ID: str = ''


def watch_reaction(alert: dict, analysis: str, msg_id: str) -> None:
    """Poll for yes/no reaction, then act. Runs in a background thread."""
    deadline = time.time() + REACTION_TIMEOUT
    name = alert['labels'].get('alertname', 'Unknown')

    while time.time() < deadline:
        time.sleep(10)

        yes_users = get_reactions(msg_id, REACT_YES)
        # Exclude the bot's own reaction
        human_yes = [u for u in yes_users if u.get('id') != BOT_USER_ID]
        if human_yes:
            log.info('User approved remediation for %s', name)
            bot_update(msg_id, f'⚙️ HolmesGPT is attempting to fix **{name}**...')
            try:
                result = remediate(alert, analysis)
            except Exception as exc:
                result = f'Remediation failed: {exc}'
                log.error('Remediation error for %s: %s', name, exc)
            log.info('Remediation complete for %s', name)
            bot_update(msg_id, f'**Remediation result for {name}:**\n{result[:1800]}')
            return

        no_users = get_reactions(msg_id, REACT_NO)
        human_no = [u for u in no_users if u.get('id') != BOT_USER_ID]
        if human_no:
            log.info('User declined remediation for %s', name)
            bot_update(msg_id, f'❌ Remediation skipped for **{name}**.')
            return

    log.info('Reaction timeout for %s — no action taken', name)
    bot_update(msg_id, f'⏱️ No response received for **{name}** — remediation skipped.')


# ---------- Discord webhook fallback (kept for initial posting if bot fails) ----------

def post_webhook_fallback(alert: dict, analysis: str) -> None:
    name = alert['labels'].get('alertname', 'Unknown')
    severity = alert['labels'].get('severity', 'info').lower()
    color = SEVERITY_COLORS.get(severity, DEFAULT_COLOR)
    embed = {
        'title': f'\U0001f6a8 {name}',
        'description': analysis[:3800],
        'color': color,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'footer': {'text': f'Severity: {severity.upper()} • via HolmesGPT'},
    }
    requests.post(DISCORD_WEBHOOK_URL, json={'embeds': [embed]}, timeout=10)


# ---------- Main poll loop ----------

def process_alert(alert: dict) -> None:
    name = alert['labels'].get('alertname', 'Unknown')
    fp = alert['fingerprint']

    log.info('Calling HolmesGPT for alert: %s (%s)', name, fp)
    try:
        analysis = investigate(alert)
    except Exception as exc:
        log.error('HolmesGPT call failed for %s: %s', name, exc)
        analysis = f'HolmesGPT unavailable: {exc}'
    log.info('Analysis received (%d chars) for %s', len(analysis), name)

    try:
        msg_id = bot_post(alert, analysis)
        add_reactions(msg_id)
        t = threading.Thread(
            target=watch_reaction, args=(alert, analysis, msg_id), daemon=True
        )
        t.start()
    except Exception as exc:
        log.error('Discord bot post failed for %s: %s — falling back to webhook', name, exc)
        try:
            post_webhook_fallback(alert, analysis)
        except Exception as exc2:
            log.error('Webhook fallback also failed for %s: %s', name, exc2)


def poll() -> None:
    global last_firing

    try:
        alerts = get_firing_alerts()
    except Exception as exc:
        log.error('Alertmanager poll failed: %s', exc)
        return

    current = {a['fingerprint'] for a in alerts}

    resolved = last_firing - current
    if resolved:
        log.info('Resolved fingerprints cleared from dedup: %s', resolved)
        processed.difference_update(resolved)
    last_firing = current

    new_alerts = [
        a for a in alerts
        if a['fingerprint'] not in processed
        and a['labels'].get('alertname') not in IGNORED_ALERTS
    ]
    log.info('Poll complete: %d firing, %d new', len(alerts), len(new_alerts))

    for alert in new_alerts:
        processed.add(alert['fingerprint'])
        process_alert(alert)


def main() -> None:
    global BOT_USER_ID
    log.info(
        'Bridge starting — Alertmanager: %s | HolmesGPT: %s | interval: %ds | ignored: %s',
        ALERTMANAGER_URL, HOLMES_URL, POLL_INTERVAL, sorted(IGNORED_ALERTS),
    )
    try:
        BOT_USER_ID = get_bot_user_id()
        log.info('Discord bot authenticated, user_id=%s', BOT_USER_ID)
    except Exception as exc:
        log.error('Failed to authenticate Discord bot: %s', exc)

    while True:
        poll()
        time.sleep(POLL_INTERVAL)


if __name__ == '__main__':
    main()
