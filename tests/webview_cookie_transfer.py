"""Real WebView2 -> encrypted worker result -> requests integration, using only localhost."""
import json
import os
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from app.cookies import CookieManager
from app.login import LoginWindow
from app.login_ipc import read_result, write_result


@unittest.skipUnless(os.name == 'nt', 'Requires Windows WebView2 and DPAPI')
class WebviewTransfer(unittest.TestCase):
    def test_httponly_session_reaches_authenticated_request_after_window_closes(self):
        import webview

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                if self.path == '/verify':
                    self.end_headers()
                    authenticated = 'NTES_SESS=dummy-session' in self.headers.get('Cookie', '')
                    self.wfile.write(json.dumps({'authenticated': authenticated}).encode())
                else:
                    self.send_header('Set-Cookie', 'NTES_SESS=dummy-session; HttpOnly; Path=/; SameSite=Lax')
                    self.send_header('Set-Cookie', 'persistent=dummy-persistent; Max-Age=86400; Path=/')
                    self.end_headers()
                    self.wfile.write(b'<html><body>Local login transport test</body></html>')

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        url = 'http://127.0.0.1:%d/' % server.server_port
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'worker-result.json'
            errors = []
            window = webview.create_window('MOOC local cookie transport test', url, hidden=True)

            def capture(win):
                try:
                    if not win.events.loaded.wait(20):
                        raise RuntimeError('WebView2 page load timed out')
                    records = LoginWindow._read_records(win)
                    write_result(path, {'ok': True, 'records': records, 'user': {'id': '42'}})
                except Exception as error:
                    errors.append(type(error).__name__)
                finally:
                    win.destroy()

            webview.start(capture, (window,), gui='edgechromium', private_mode=True)
            self.assertEqual(errors, [])
            self.assertNotIn('dummy-session', path.read_text(encoding='utf-8'))
            result = read_result(path)
            manager = CookieManager(str(Path(folder) / 'unused.json'))
            manager.records = result['records']
            session_cookie = next(c for c in manager.records if c['name'] == 'NTES_SESS')
            with manager.build_session() as session:
                response = session.get(url + 'verify', timeout=5)
                self.assertTrue(response.json()['authenticated'], 'Session cookie was lost between WebView2 and requests')
            self.assertIsNone(session_cookie['expires'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
