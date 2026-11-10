"""Offline regressions for the login-page object format and video classification."""
import sys
import tempfile
import unittest
from http.cookies import SimpleCookie
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.icourse_api import CourseClient, LoginExpired, PaidCourseError, ResourceUnavailable
from app.models import Unit
from app.login import LoginWindow
from app.cookies import CookieManager


class CookieTransfer(unittest.TestCase):
    def records(self, expires):
        cookie = SimpleCookie()
        cookie['NTES_SESS'] = 'dummy-session'
        cookie['NTES_SESS']['domain'] = '.icourse163.org'
        cookie['NTES_SESS']['path'] = '/'
        cookie['NTES_SESS']['secure'] = True
        cookie['NTES_SESS']['httponly'] = True
        if expires:
            cookie['NTES_SESS']['expires'] = expires
        return LoginWindow._read_records(NS(get_cookies=lambda: [cookie]))

    def cookie_header(self, records):
        with tempfile.TemporaryDirectory() as folder:
            manager = CookieManager(str(Path(folder) / 'unused.json'))
            manager.records = records
            with manager.build_session() as session:
                import requests
                request = session.prepare_request(requests.Request('GET', 'https://www.icourse163.org/'))
                return request.headers.get('Cookie', '')

    def test_webview_session_expiry_sentinel_is_not_a_past_expiry(self):
        records = self.records('Mon, 01 Jan 0001 00:00:00 GMT')
        self.assertIsNone(records[0]['expires'])
        self.assertIn('NTES_SESS=dummy-session', self.cookie_header(records))

    def test_actual_expired_cookie_stays_expired(self):
        records = self.records('Mon, 01 Jan 2001 00:00:00 GMT')
        self.assertNotIn('NTES_SESS', self.cookie_header(records))

    def test_future_and_ordinary_session_cookies_remain_usable(self):
        for expires in ['', 'Mon, 01 Jan 2035 00:00:00 GMT']:
            with self.subTest(expires=expires):
                self.assertIn('NTES_SESS=dummy-session', self.cookie_header(self.records(expires)))

    def test_session_survives_encrypted_save_and_restart(self):
        records = self.records('Mon, 01 Jan 0001 00:00:00 GMT')
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'account.json'
            manager = CookieManager(str(path))
            manager.save(records, {'id': '42', 'nickName': 'Example'})
            self.assertNotIn('dummy-session', path.read_text(encoding='utf-8'))
            restored = CookieManager(str(path))
            self.assertIn('NTES_SESS=dummy-session', self.cookie_header(restored.records))


class LoginPage(unittest.TestCase):
    def setUp(self):
        self.client = CourseClient()
        self.addCleanup(self.client.session.close)

    def verify(self, value):
        page = '<script>window.webUser = ' + value + ';window.other = {id:"999"};</script>'
        with patch.object(self.client, '_get_page', return_value=page):
            return self.client.verify_identity()

    def test_live_page_object_with_unquoted_keys(self):
        self.assertEqual(self.verify('{rightsTime:"0",id:"42",nickName:"测试",roles:[],end_key:0}'),
                         {'id': '42', 'nickName': '测试'})
        self.assertEqual(self.client.web_user_id, '42')

    def test_json_page_remains_supported(self):
        self.assertEqual(self.verify('{"id":42,"nickname":"Example"}'),
                         {'id': '42', 'nickName': 'Example'})

    def test_nickname_with_statement_delimiters(self):
        self.assertEqual(self.verify(r'{id:"42",nickName:"名字; } { \"引用\""}')['nickName'],
                         '名字; } { "引用"')

    def test_single_quoted_page_object(self):
        self.assertEqual(self.verify(r"{id:'42',nickName:'O\'Brien; 测试',roles:[],}")['nickName'],
                         "O'Brien; 测试")

    def test_guest_or_malformed_page_never_logs_in(self):
        for value in ['null', '{}', '{nickName:"guest"}', '{id:"42"',
                      '{id:Math.random()}', '{id:"42"}.other', '[]']:
            with self.subTest(value=value), self.assertRaises(LoginExpired):
                self.verify(value)

    def test_course_retains_identity_for_resource_signatures(self):
        page = '<script>window.webUser={id:"42",nickName:"测试"};termId:"123";</script>'
        with patch.object(self.client, 'warmup'), \
             patch.object(self.client, '_get_page', return_value=page), \
             patch.object(self.client, '_dwr', return_value={'name': 'Example'}):
            self.client.load_course('https://www.icourse163.org/course/SHUFE-1486311164')
        self.assertEqual(self.client.web_user_id, '42')


class VideoClassification(unittest.TestCase):
    def setUp(self):
        self.client = CourseClient()
        self.addCleanup(self.client.session.close)

    def resolve(self, variants, status=0):
        token = {'result': {'videoSignDto': {'status': status, 'signature': 'test'}}}
        vod = {'code': 0, 'result': {'videos': variants, 'duration': 10}}
        with patch.object(self.client, 'warmup', return_value='test'), \
             patch.object(self.client, '_post', return_value=NS(json=lambda: token)), \
             patch.object(self.client, '_get', return_value=NS(json=lambda: vod)):
            return self.client.get_video_urls(Unit(content_id=123), '高清优先')

    def test_encryption_is_not_reported_as_a_paid_course(self):
        item = {'format': 'hls', 'videoUrl': 'https://example.org/encrypted.m3u8',
                'e': True, 'secondaryEncrypt': True, 'k': 'test'}
        with self.assertRaises(ResourceUnavailable) as raised:
            self.resolve([item])
        self.assertNotIsInstance(raised.exception, PaidCourseError)

    def test_clear_variant_can_be_used_beside_encrypted_variant(self):
        items = [{'format': 'hls', 'videoUrl': 'https://example.org/encrypted.m3u8', 'e': True},
                 {'format': 'mp4', 'videoUrl': 'https://example.org/clear_hd.mp4', 'e': False}]
        self.assertEqual(self.resolve(items)[:2], ('https://example.org/clear_hd.mp4', 'mp4'))

    def test_denied_authorization_still_stops_download(self):
        with self.assertRaises(PaidCourseError):
            self.resolve([], status=403)


if __name__ == '__main__':
    unittest.main(verbosity=2)
