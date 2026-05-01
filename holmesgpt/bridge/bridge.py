#!/usr/bin/env python3
import os
import time
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
    'http://holmesgpt-holmes.holmesgpt.svc.cluster.local:5050',
)
DISCORD_WEBHOOK_URL = os.environ['DISCORD_WEBHOOK_URL']
POLL_INTERVAL = int(os.environ.get('POLL_INTERVAL', '60'))
# Comma-separated alert names to never process (e.g. always-on noise alerts)
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

# fingerprint -> True for alerts currently firing that have been posted
processed: set[str] = set()
# all fingerprints seen in last cycle (for detecting resolves)
last_firing: set[str] = set()


def get_firing_alerts() -> list[dict]:
    resp = requests.get(
        f'{ALERTMANAGER_URL}/api/v2/alerts',
        params={'active': 'true', 'silenced': 'false', 'inhibited': 'false'},
        timeout=10,
    )
    resp.raise_for_status()
    return [a for a in resp.json() if a.get('status', {}).get('state') == 'active']


def call_holmesgpt(alert: dict) -> str:
    name = alert['labels'].get('alertname', 'Unknown')
    desc = (
        alert['annotations'].get('description')
        or alert['annotations'].get('summary')
        or 'No description provided'
    )
    question = (
        f'Investigate this alert and provide root cause and suggested fix: {name} - {desc}'
    )
    resp = requests.post(
        f'{HOLMES_URL}/api/chat',
        json={'ask': question},
        timeout=180,
    )
    resp.raise_for_status()
    return resp.json().get('analysis', 'No analysis returned.')


def post_to_discord(alert: dict, analysis: str) -> None:
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
    lines.append(f'**HolmesGPT Analysis:**')
    # Discord embed description limit is 4096 chars; reserve room for header lines
    lines.append(analysis[:3800])

    embed = {
        'title': f'\U0001f6a8 {name}',
        'description': '\n'.join(lines),
        'color': color,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'footer': {'text': f'Severity: {severity.upper()} • via HolmesGPT'},
    }
    resp = requests.post(DISCORD_WEBHOOK_URL, json={'embeds': [embed]}, timeout=10)
    resp.raise_for_status()
    log.info('Posted Discord embed for alert: %s', name)


def poll() -> None:
    global last_firing

    try:
        alerts = get_firing_alerts()
    except Exception as exc:
        log.error('Alertmanager poll failed: %s', exc)
        return

    current = {a['fingerprint'] for a in alerts}

    # Detect resolved alerts and clear dedup so they fire again if they come back
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
        fp = alert['fingerprint']
        name = alert['labels'].get('alertname', 'Unknown')
        # Mark processed immediately so a crash mid-flight doesn't double-post on next cycle
        processed.add(fp)
        log.info('Calling HolmesGPT for alert: %s (%s)', name, fp)
        try:
            analysis = call_holmesgpt(alert)
        except Exception as exc:
            log.error('HolmesGPT call failed for %s: %s', name, exc)
            analysis = f'HolmesGPT unavailable: {exc}'
        log.info('Analysis received (%d chars) for %s', len(analysis), name)
        try:
            post_to_discord(alert, analysis)
        except Exception as exc:
            log.error('Discord post failed for %s: %s', name, exc)


def main() -> None:
    log.info(
        'Bridge starting — Alertmanager: %s | HolmesGPT: %s | interval: %ds | ignored: %s',
        ALERTMANAGER_URL, HOLMES_URL, POLL_INTERVAL, sorted(IGNORED_ALERTS),
    )
    while True:
        poll()
        time.sleep(POLL_INTERVAL)


if __name__ == '__main__':
    main()
