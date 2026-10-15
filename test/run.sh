#!/usr/bin/env bash
# Runs scan.sh against a local fake Bugsieve and checks the exit code for each situation.
set -u
cd "$(dirname "$0")/.."
PORT=18765
fail=0

serve() { # serve <mode>
  python3 - "$1" "$PORT" <<'PY' &
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
mode, port = sys.argv[1], int(sys.argv[2])
counts = {'ok': dict(critical=1, high=2, medium=0, exploited=0, total=3), 'exploited': dict(critical=0, high=0, medium=0, exploited=1, total=1), 'clean': dict(critical=0, high=0, medium=0, exploited=0, total=0)}.get(mode, {})
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def send(self, code, body):
        data = json.dumps(body).encode(); self.send_response(code); self.send_header('Content-Type', 'application/json'); self.send_header('Content-Length', str(len(data))); self.end_headers(); self.wfile.write(data)
    def do_POST(self):
        self.rfile.read(int(self.headers.get('Content-Length', 0)))
        if mode == 'down': return self.send(522, {})
        if mode == 'cfblock':
            data = b'<html>Attention Required! Cloudflare</html>'; self.send_response(403); self.send_header('Content-Type', 'text/html'); self.send_header('Content-Length', str(len(data))); self.end_headers(); return self.wfile.write(data)
        if mode == 'badtoken': return self.send(401, {'message': 'Unauthenticated.'})
        if mode == 'limit': return self.send(429, {'message': 'Daily scan limit reached.'})
        self.send(202, {'data': {'id': 7}})
    def do_GET(self):
        if mode == 'scanfailed': return self.send(200, {'data': {'status': 'failed', 'failure': 'clone failed', 'links': {'web': 'x'}}})
        self.send(200, {'data': {'status': 'completed', 'repository': 'acme/app', 'branch': 'main', 'counts': counts, 'links': {'web': 'https://bugsieve.test/r'}}})
HTTPServer(('127.0.0.1', port), H).serve_forever()
PY
  PID=$!; sleep 0.6
}

check() { # check <name> <mode> <fail-on> <strict> <expected exit>
  serve "$2"
  BUGSIEVE_SERVER="http://127.0.0.1:$PORT" BUGSIEVE_TOKEN=tok BUGSIEVE_REPOSITORY=https://github.com/acme/app BUGSIEVE_REF=main \
    BUGSIEVE_FAIL_ON="$3" BUGSIEVE_STRICT="$4" BUGSIEVE_TIMEOUT_MINUTES=1 BUGSIEVE_POLL_SECONDS=0 ./scan.sh >/dev/null 2>&1
  got=$?
  kill $PID 2>/dev/null; wait $PID 2>/dev/null
  if [[ "$got" == "$5" ]]; then echo "ok   $1"; else echo "FAIL $1: exit $got, expected $5"; fail=1; fi
}

check "high fails on 1 critical + 2 high"        ok        high      false 1
check "critical fails on 1 critical"             ok        critical  false 1
check "exploited passes when none exploited"     ok        exploited false 0
check "exploited fails on 1 exploited"           exploited exploited false 1
check "medium fails on 1 exploited"              exploited medium    false 1
check "none never fails on findings"             ok        none      false 0
check "clean scan passes at medium"              clean     medium    false 0
check "bad fail-on value fails"                  ok        bogus     false 1
check "outage (522) passes by default"           down      high      false 0
check "outage (522) fails in strict mode"        down      high      true  1
check "bad token fails"                          badtoken  high      false 1
check "firewall page passes by default"          cfblock   high      false 0
check "firewall page fails in strict mode"       cfblock   high      true  1
check "scan limit passes"                        limit     high      false 0
check "failed scan fails"                        scanfailed high     false 1

# nothing listening at all
BUGSIEVE_SERVER="http://127.0.0.1:1" BUGSIEVE_TOKEN=tok BUGSIEVE_REPOSITORY=x BUGSIEVE_REF=main BUGSIEVE_FAIL_ON=high BUGSIEVE_STRICT=false BUGSIEVE_TIMEOUT_MINUTES=1 ./scan.sh >/dev/null 2>&1
[[ $? == 0 ]] && echo "ok   no connection passes by default" || { echo "FAIL no connection should pass by default"; fail=1; }

exit $fail
