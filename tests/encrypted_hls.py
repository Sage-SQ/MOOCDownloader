"""Synthetic AES playback fixtures; no real account, keys or video URLs."""
import base64
import json
import subprocess
import sys
import tempfile
import threading
import unittest
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from app import config
from app.downloader import DownloadManager, InterruptedError_, completed
from app.icourse_api import CourseClient, ResourceUnavailable
from app.models import Unit

try:
    from app import hls_crypto
except ImportError:
    hls_crypto = None

ITEM = {'k': 'AAECAwQFBgcICQoLDA0ODy98E1NijkfxYpAuixGAoLm4FP13u8MMdA0OZ+nOq/GU20L5ND5vD4mHLW1wrGs9QQ==',
        'v': 0, 'videoUrl': 'https://vod.study.163.com/eds/api/v1/vod/video/1234567890/hls/m3u8?quality=1&isNative=false',
        'format': 'hls', 'e': True, 'secondaryEncrypt': True, 'quality': 1}


def envelope(content, key):
    iv = bytes(range(16))
    return base64.b64encode(iv + AES.new(key, AES.MODE_CBC, iv).encrypt(pad(content, 16)))


class PlaybackCrypto(unittest.TestCase):
    def require_support(self):
        self.assertIsNotNone(hls_crypto, 'Encrypted HLS playback support is missing')

    def test_site_js_fixture_formats_authorized_url(self):
        self.require_support()
        url = hls_crypto.authorize_url(ITEM, now=1794182400)
        self.assertEqual(urlsplit(url).path, '/eds/api/v1/vod/video/c/1234567890/hls/m3u8')
        query = parse_qs(urlsplit(url).query)
        self.assertEqual(query['token'], ['https://example.org/test-token?a=1&b=2'])
        self.assertEqual(query['t'], ['1794182400000'])
        self.assertEqual(query['quality'], ['1'])

    def test_secondary_manifest_and_key_have_distinct_wrapping_keys(self):
        self.require_support()
        now = datetime(2026, 11, 9, 8)
        manifest = b'#EXTM3U\n#EXT-X-ENDLIST\n'
        encoded = envelope(manifest, b'5678908817942026').hex()
        self.assertEqual(hls_crypto.secondary_decrypt(encoded, 1234567890, now=now), manifest)
        encoded_key = envelope(b'00112233445566778899aabbccddeeff', b'4567890661794026').hex()
        self.assertEqual(hls_crypto.secondary_decrypt(encoded_key, 1234567890, is_key=True, now=now), bytes.fromhex('00112233445566778899aabbccddeeff'))

    def test_unknown_key_version_and_corrupt_envelope_fail_closed(self):
        self.require_support()
        for item in (dict(ITEM, v=1000), dict(ITEM, k='not-base64')):
            with self.subTest(version=item['v']), self.assertRaises(ValueError):
                hls_crypto.authorize_url(item)

    def test_live_or_truncated_secondary_manifest_is_not_marked_complete(self):
        self.require_support()
        encoded = envelope(b'#EXTM3U\n#EXTINF:1,\na.ts\n', b'5678908817942026').hex()
        with self.assertRaises(ValueError):
            hls_crypto.secondary_decrypt(encoded, 1234567890, now=datetime(2026, 11, 9, 8))

    def test_endpoint_quality_tiers_honor_all_preferences(self):
        items = [dict(ITEM, quality=rank, videoUrl=ITEM['videoUrl'].replace('quality=1', 'quality='+str(rank))) for rank in (1, 2, 3)]
        for rank, preference in enumerate(config.QUALITY_OPTIONS, 1):
            with self.subTest(preference=preference):
                url, _, label = CourseClient._pick_quality(items, preference)
                self.assertEqual(parse_qs(urlsplit(url).query)['quality'], [str(rank)])
                self.assertIn('源站档位', label)

    def test_aes_segment_uses_sequence_iv_and_rejects_wrong_key(self):
        self.require_support()
        plain = b'video transport bytes' * 13
        key = bytes(range(16))
        encrypted = AES.new(key, AES.MODE_CBC, (7).to_bytes(16, 'big')).encrypt(pad(plain, 16))
        self.assertEqual(hls_crypto.decrypt_segment(encrypted, key, 7), plain)
        with self.assertRaises(ValueError):
            hls_crypto.decrypt_segment(encrypted, b'wrong-key-0000000', 7)

    def test_explicit_iv_overrides_sequence(self):
        self.require_support()
        key = bytes(range(16))
        iv = (99).to_bytes(16, 'big')
        encrypted = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(b'explicit IV', 16))
        self.assertEqual(hls_crypto.decrypt_segment(encrypted, key, 7, '0x63'), b'explicit IV')

    def test_timestamp_refresh_does_not_invalidate_partial_cache(self):
        from app.downloader import identity
        a = 'https://example.org/a.ts?quality=1&token=old&t=1'
        b = 'https://example.org/a.ts?quality=1&token=new&t=2'
        self.assertEqual(identity(a), identity(b))

    def test_resolver_accepts_supported_encryption_after_authorization(self):
        client = CourseClient()
        self.addCleanup(client.session.close)
        rpc = {'result': {'videoSignDto': {'status': 0, 'signature': 'dummy'}}}
        vod = {'code': 0, 'result': {'videos': [ITEM], 'duration': 12}}
        unit = Unit(content_id=1234567890)
        with patch.object(client, 'warmup', return_value='dummy'), patch.object(client, '_post', return_value=NS(json=lambda: rpc)), patch.object(client, '_get', return_value=NS(json=lambda: vod)):
            url, fmt, _, duration = client.get_video_urls(unit, '标清优先')
        self.assertEqual(fmt, 'hls')
        self.assertEqual(duration, 12)
        self.assertTrue(parse_qs(urlsplit(url).query).get('token'))
        self.assertEqual(unit._secondary_video_id, 1234567890)


class EncryptedDownload(unittest.TestCase):
    def test_sample_aes_is_rejected_before_segment_download(self):
        session = requests.Session()
        manager = DownloadManager(session, lambda *_: None, lambda *_: None, local_metadata=True)
        with tempfile.TemporaryDirectory() as directory:
            text = '#EXTM3U\n#EXT-X-KEY:METHOD=SAMPLE-AES,URI="key"\n#EXTINF:1,\na.ts\n#EXT-X-ENDLIST\n'
            try:
                with patch.object(manager, '_fetch', return_value=text), self.assertRaises(ResourceUnavailable):
                    manager._download_hls('https://example.org/manifest', Path(directory)/'out.mp4', config.find_ffmpeg())
            finally:
                manager.close()
                session.close()

    def test_secondary_hls_download_produces_decodable_mp4(self):
        self.assertIsNotNone(hls_crypto, 'Encrypted HLS playback support is missing')
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            source = folder / 'fixture.ts'
            subprocess.run([config.find_ffmpeg(), '-v', 'error', '-f', 'lavfi', '-i', 'testsrc2=size=160x90:rate=10', '-t', '1', '-c:v', 'libx264', '-f', 'mpegts', str(source)], check=True, timeout=20)
            key = bytes(range(16))
            # IV is media sequence 7, not the segment's zero-based index.
            encrypted = AES.new(key, AES.MODE_CBC, (7).to_bytes(16, 'big')).encrypt(pad(source.read_bytes(), 16))
            now = datetime(2026, 11, 9, 8)
            manifest = '#EXTM3U\n#EXT-X-VERSION:3\n#EXT-X-TARGETDURATION:1\n#EXT-X-MEDIA-SEQUENCE:7\n#EXT-X-KEY:METHOD=AES-128,URI="key"\n#EXTINF:1,\nsegment.ts\n#EXT-X-ENDLIST\n'
            bodies = {'/manifest': envelope(manifest.encode(), b'5678908817942026').hex().encode(), '/key': envelope(key.hex().encode(), b'4567890661794026').hex().encode(), '/segment.ts': encrypted}
            requested = []
            class Handler(BaseHTTPRequestHandler):
                def do_GET(self):
                    requested.append(urlsplit(self.path).path)
                    content = bodies.get(urlsplit(self.path).path)
                    self.send_response(200 if content is not None else 404)
                    self.send_header('Content-Length', str(len(content or b'')))
                    self.end_headers()
                    self.wfile.write(content or b'')
                def log_message(self, *args):
                    pass
            server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            session = requests.Session()
            manager = DownloadManager(session, lambda *_: None, lambda *_: None, local_metadata=True)
            output = folder / 'result.mp4'
            try:
                with patch('app.hls_crypto.datetime') as clock:
                    clock.now.return_value = now
                    # Pause after transfer; the resumed run must use cached segments.
                    def pause(_):
                        manager.stop()
                    with self.assertRaises(InterruptedError_):
                        manager._download_hls('http://127.0.0.1:%d/manifest' % server.server_port, output, config.find_ffmpeg(), progress_cb=pause, secondary_video_id=1234567890)
                    self.assertFalse(output.exists())
                    self.assertTrue(Path(str(output)+'.parts').exists())
                    manager._stop.clear()
                    manager._download_hls('http://127.0.0.1:%d/manifest' % server.server_port, output, config.find_ffmpeg(), secondary_video_id=1234567890)
                self.assertEqual(requested.count('/segment.ts'), 1)
                self.assertTrue(completed(output, local=True))
                result = subprocess.run([config.find_ffmpeg(), '-v', 'error', '-xerror', '-i', str(output), '-f', 'null', '-'], capture_output=True, timeout=20)
                self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
                self.assertFalse(Path(str(output)+'.parts').exists())
            finally:
                manager.close()
                session.close()
                server.shutdown()
                server.server_close()
                thread.join(5)


if __name__ == '__main__':
    unittest.main(verbosity=2)
