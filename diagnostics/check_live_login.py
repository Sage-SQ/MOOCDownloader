"""Interactive app-login check. Stores only a redacted summary, never cookie values."""
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from app.cookies import CookieManager
from app.icourse_api import CourseClient
from app.login import LoginWindow
from app.login_ipc import read_result, write_result

summary = {'window_completed': False, 'identity_verified': False, 'restored_identity_verified': False}
try:
    result = LoginWindow().open()
    summary['window_completed'] = bool(result.get('ok'))
    if result.get('ok'):
        with tempfile.TemporaryDirectory() as folder:
            transport = Path(folder) / 'login-result.json'
            write_result(transport, result)
            received = read_result(transport)
            candidate = CookieManager(str(Path(folder) / 'account.json'))
            candidate.records = received.get('records') or []
            summary['native_record_count'] = len(candidate.records)
            with candidate.build_session() as session:
                summary['retained_cookie_count'] = len(session.cookies)
                client = CourseClient(session)
                user = client.verify_identity()
                summary['identity_verified'] = bool(user.get('id'))
            candidate.save(candidate.records, user)
            restored = CookieManager(str(candidate.path))
            with restored.build_session() as session:
                summary['restored_identity_verified'] = bool(CourseClient(session).verify_identity().get('id'))
except Exception as error:
    summary['error_type'] = type(error).__name__
    # The error text and response can contain site data; intentionally omit both.
finally:
    output = ROOT / '_test_tmp' / 'live-login-local.2-summary.json'
    output.parent.mkdir(exist_ok=True)
    output.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(summary, ensure_ascii=False, indent=2), flush=True)
