"""Render only selected HTTP backends, then exec Apache without root privileges."""
import html
import json
import os
from pathlib import Path
import re
import subprocess


def render(raw):
    if len(raw.encode()) > 16384:
        raise ValueError("HTTP target configuration exceeds the limit")
    targets = json.loads(raw)
    if not isinstance(targets, list) or len(targets) > 32:
        raise ValueError("Expected at most 32 selected targets")
    names, services = set(), []
    for target in targets:
        if not isinstance(target, dict) or set(target) != {"id", "service", "port"}:
            raise ValueError("Invalid target descriptor")
        for key, length in (("id", 40), ("service", 62)):
            if not isinstance(target[key], str) or not re.fullmatch(r"[a-z][a-z0-9-]{0," + str(length) + r"}", target[key]):
                raise ValueError("Invalid HTTP target identifier")
        if type(target["port"]) is not int or not 1 <= target["port"] <= 65535 or target["id"] in names:
            raise ValueError("Duplicate target or invalid port")
        names.add(target["id"])
        services.append(target)
    console = ['Include /etc/xoc/console.conf'] if os.environ.get('XOC_POLICY_STATE') == '1' else []
    lines = ['<VirtualHost *:8080>', 'ServerName core.xoc.test', 'DocumentRoot /run/apache2/site',
             '<Directory /run/apache2/site>', 'Require all granted', '</Directory>'] + console + ['</VirtualHost>']
    links = []
    for target in sorted(services, key=lambda t: t["id"]):
        host = target["id"] + ".xoc.test"
        backend = f'http://{target["service"]}:{target["port"]}/'
        lines.extend(['<VirtualHost *:8080>', f'ServerName {host}', 'ProxyPreserveHost On',
                      f'ProxyPass / {backend}', f'ProxyPassReverse / {backend}'] + console + ['</VirtualHost>'])
        links.append(f'<li><a href="http://{host}:8080/">{html.escape(target["id"])}</a></li>')
    page = '<!doctype html><html lang="en"><meta charset="utf-8"><title>xOC Core lab</title><h1>xOC Core security-path lab</h1>'
    page += '<p>Experimental gateway. Selected targets require lab DNS or a matching Host header.</p><ul>' + ''.join(links) + '</ul></html>'
    return '\n'.join(lines) + '\n', page


if __name__ == "__main__":
    try:
        config, page = render(os.environ.get("XOC_WEB_TARGETS", "[]"))
    except (ValueError, TypeError):
        raise SystemExit("Invalid selected-target configuration")
    base = Path("/run/apache2")
    (base / "site").mkdir(exist_ok=True)
    (base / "lock").mkdir(exist_ok=True)
    (base / "xoc-sites.conf").write_text(config)
    (base / "site/index.html").write_text(page)
    (base / "site/healthz").write_text('{"service":"xoc-web","status":"experimental"}\n')
    (base / 'xoc-siem-route.conf').write_text('Include /etc/xoc/siem.conf\n' if os.environ.get('XOC_SIEM_UI') == '1' else '')
    if os.environ.get('XOC_MANAGEMENT') == '1':
        with (base / 'xoc-sites.conf').open('a') as stream:
            stream.write('\nInclude /etc/xoc/management.conf\n')
    if os.environ.get("XOC_POLICY_STATE") == "1":
        subprocess.run(["python3", "-B", "/usr/local/lib/xoc/console/broker.py", "waf", "init"], check=True)
    if os.environ.get("XOC_CONSOLE") == "1":
        subprocess.Popen(["python3", "-B", "/usr/local/lib/xoc/console/broker.py", "waf"])
    subprocess.run(["apache2ctl", "configtest"], check=True)
    os.execvp("apache2ctl", ["apache2ctl", "-D", "FOREGROUND"])
