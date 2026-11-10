"""MOOC web-player envelopes and standard HLS AES-128 segments.

Protocol observed in videoAesUtilsMin_204f9019ddbd47da07f40a4dc117821b.js
and VIDEOPLAYER_a7718dbce0f38d36548068efb672bcf6.js (2026-11-09).
Only server-authorized playback responses are consumed; no keys are logged.
"""
import base64
import json
import re
import time
from datetime import datetime
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# Public player wrapping versions, separate from per-video playback keys.
_WRAPPING_KEYS = ('c972aec118fee69f', '3fp4xs922ouw5q72',
                  'QHhYrEeSMFSEaWlG', 'SehYrPeSlFSoaWl5')


def _open_envelope(data, key):
    packed = base64.b64decode(data, validate=True)
    if len(packed) < 32 or len(packed) % 16:
        raise ValueError('Invalid playback envelope')
    return unpad(AES.new(key, AES.MODE_CBC, packed[:16]).decrypt(packed[16:]), 16)


def authorize_url(item, now=None):
    """Decode the supplied playback token and format the web HLS endpoint."""
    try:
        version = int(item['v'])
        if version < 0 or version >= len(_WRAPPING_KEYS):
            raise ValueError('Unknown playback wrapping version')
        decoded = _open_envelope(item['k'], _WRAPPING_KEYS[version].encode())
        token_data = json.loads(decoded.decode('utf-8'))
        token = token_data.get('k') or token_data.get('videoDecryptionKey')
        if not isinstance(token, str) or not token:
            raise ValueError('Missing playback token')
        parts = urlsplit(item['videoUrl'])
        if parts.scheme not in ('http', 'https'):
            raise ValueError('Invalid playback URL')
        token = re.sub(r'^(?:https?:)?//', parts.scheme + '://', token)
        path = re.sub(r'/video/(\d+)/hls/m3u8', r'/video/c/\1/hls/m3u8', parts.path)
        query = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
                 if k not in ('token', 't')]
        query += [('token', token), ('t', str(int((time.time() if now is None else now) * 1000)))]
        return urlunsplit(parts._replace(path=path, query=urlencode(query)))
    except (KeyError, TypeError, UnicodeError, ValueError) as error:
        raise ValueError('无法解析源站播放授权，可能是加密协议已更新') from error


def secondary_decrypt(data, video_id, is_key=False, now=None):
    """Decode the player's hex/base64/AES envelope, leaving segments to HLS."""
    now = now or datetime.now()
    stamp = str(int(now.timestamp() * 1000))[:4]
    identifier = str(video_id)
    if not identifier.isdigit():
        raise ValueError('Invalid video identifier')
    if is_key:
        wrapping = identifier[-7:] + '66' + stamp + str(now.year)[-3:]
    else:
        wrapping = identifier[-6:] + '88' + stamp + str(now.year)
    try:
        encoded = bytes.fromhex(data.decode('ascii') if isinstance(data, bytes) else data)
        plain = _open_envelope(encoded, wrapping.encode())
        if is_key:
            key = bytes.fromhex(plain[:32].decode('ascii'))
            if len(key) != 16:
                raise ValueError('Invalid HLS key')
            return key
        if not plain.lstrip().startswith(b'#EXTM3U'):
            raise ValueError('Invalid HLS playlist')
        if b'#EXT-X-ENDLIST' not in plain:
            raise ValueError('Live or incomplete HLS playlist')
        return plain.split(b'#EXT-X-ENDLIST')[0] + b'#EXT-X-ENDLIST\n'
    except (UnicodeError, ValueError) as error:
        raise ValueError('播放列表或密钥解码失败，请检查系统时间或重新解析课程') from error


def decrypt_segment(data, key, sequence, iv=None):
    if len(key) != 16 or not data or len(data) % 16:
        raise ValueError('无效的 AES-128 视频分片')
    if iv:
        iv_bytes = int(iv, 16).to_bytes(16, 'big')
    else:
        iv_bytes = int(sequence).to_bytes(16, 'big')
    return unpad(AES.new(key, AES.MODE_CBC, iv_bytes).decrypt(data), 16)
