"""Unit tests for web reverse engineering tools:
  - skills/apk-reverse/scripts/sourcemap_extractor.py
  - skills/apk-reverse/scripts/web_api_tracer.py
  - skills/apk-reverse/scripts/js_deobfuscator.py
  - skills/apk-reverse/scripts/web_modifier.py
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import pytest

from conftest import load_script

sourcemap_extractor = load_script("sourcemap_extractor.py")
web_api_tracer = load_script("web_api_tracer.py")
js_deobfuscator = load_script("js_deobfuscator.py")
web_modifier = load_script("web_modifier.py")

pytestmark = pytest.mark.unit


# --------------------------------------------------------------------------- #
# sourcemap_extractor tests
# --------------------------------------------------------------------------- #
class TestSourcemapExtractor:
    def test_sanitize_path_strips_webpack_and_illegal_chars(self):
        raw = "webpack:///src/components/MyComponent:test.vue?vue&type=script"
        clean = sourcemap_extractor._sanitize_path(raw)
        assert clean == os.path.join("src", "components", "MyComponent_test.vue")

    def test_sanitize_path_prevents_traversal(self):
        raw = "../../../etc/passwd"
        clean = sourcemap_extractor._sanitize_path(raw)
        assert ".." not in clean
        assert clean == os.path.join("etc", "passwd")

    def test_process_js_inline_sourcemap(self):
        fake_sm = {"version": 3, "sources": ["src/index.js"], "sourcesContent": ["console.log('hello');"]}
        b64 = base64.b64encode(json.dumps(fake_sm).encode("utf-8")).decode("utf-8")
        js_code = f"console.log(1);\n//# sourceMappingURL=data:application/json;base64,{b64}"

        kind, ref, sm_json = sourcemap_extractor.process_js_text_or_url(js_code)
        assert kind == "inline"
        assert ref is None
        assert sm_json["version"] == 3
        assert sm_json["sources"] == ["src/index.js"]

    def test_process_js_remote_sourcemap(self):
        js_code = "console.log(1);\n//# sourceMappingURL=main.js.map"
        kind, ref, sm_json = sourcemap_extractor.process_js_text_or_url(js_code, "https://example.com/static/main.js")
        assert kind == "remote"
        assert ref == "https://example.com/static/main.js.map"
        assert sm_json is None

    def test_extract_sourcemap_files_to_disk(self, tmp_path):
        sm = {
            "version": 3,
            "sources": ["webpack:///src/api/auth.ts", "webpack:///src/utils/math.js"],
            "sourcesContent": [
                "export const login = () => true;",
                "export const add = (a, b) => a + b;"
            ]
        }
        out_dir = tmp_path / "extracted"
        extracted = sourcemap_extractor.extract_sourcemap_files(sm, str(out_dir))

        assert len(extracted) == 2
        auth_file = out_dir / "src" / "api" / "auth.ts"
        math_file = out_dir / "src" / "utils" / "math.js"
        assert auth_file.is_file()
        assert math_file.is_file()
        assert "export const login" in auth_file.read_text(encoding="utf-8")
        assert "export const add" in math_file.read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
# web_api_tracer tests
# --------------------------------------------------------------------------- #
class TestWebApiTracer:
    def test_analyze_javascript_detects_interceptor_and_crypto(self):
        sample_js = """
        const instance = axios.create({ baseURL: '/api/v1' });
        instance.interceptors.request.use(function (config) {
            const timestamp = Date.now();
            const sign = CryptoJS.MD5(config.url + timestamp + 'salt123').toString();
            config.headers['X-Sign'] = sign;
            config.headers['X-Timestamp'] = timestamp;
            return config;
        });
        """
        findings = web_api_tracer.analyze_javascript(sample_js)

        # Check interceptor
        assert len(findings["interceptors"]) >= 1
        assert any("Axios request interceptor" in i["type"] for i in findings["interceptors"])

        # Check crypto
        assert any("CryptoJS" in c["algorithm"] for c in findings["crypto_primitives"])
        assert any("MD5" in c["algorithm"] for c in findings["crypto_primitives"])

        # Check signature headers
        cand_matches = [c.get("matched", "") for c in findings["signature_candidates"]]
        assert any("x-sign" in m.lower() for m in cand_matches)
        assert any("x-timestamp" in m.lower() for m in cand_matches)

        # Check endpoints
        assert "/api/v1" in findings["endpoints_found"]

    def test_analyze_javascript_detects_jwt_and_decodes_claims(self):
        # A valid JWT token with payload {"sub":"user123","role":"admin"}
        # header: {"alg":"HS256","typ":"JWT"} -> eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
        # payload: {"sub":"user123","role":"admin"} -> eyJzdWIiOiJ1c2VyMTIzIiwicm9sZSI6ImFkbWluIn0
        sample_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwicm9sZSI6ImFkbWluIn0.signature456"
        sample_js = f"const defaultToken = '{sample_jwt}'; axios.defaults.headers.common['Authorization'] = defaultToken;"
        findings = web_api_tracer.analyze_javascript(sample_js)

        assert len(findings["jwt_tokens"]) >= 1
        first_jwt = findings["jwt_tokens"][0]
        assert isinstance(first_jwt["claims"], dict)
        assert first_jwt["claims"].get("sub") == "user123"
        assert first_jwt["claims"].get("role") == "admin"


# --------------------------------------------------------------------------- #
# js_deobfuscator tests
# --------------------------------------------------------------------------- #
class TestJsDeobfuscator:
    def test_decode_hex_and_unicode_escapes(self):
        raw = r"var secret = '\x68\x65\x6c\x6c\x6f \x77\x6f\x72\x6c\x64 \u0041';"
        decoded = js_deobfuscator.decode_string_escapes(raw)
        assert "hello world A" in decoded

    def test_neutralize_debugger_loops(self):
        raw = "setInterval(function(){debugger;}, 100); console.log(1); debugger;"
        clean, count = js_deobfuscator.neutralize_anti_debugging(raw)
        assert "debugger;" not in clean
        assert count >= 2
        assert "removed anti-debug loop" in clean

    def test_neutralize_debugger_function_constructor(self):
        raw = 'Function("debugger")(); eval("debugger");'
        clean, count = js_deobfuscator.neutralize_anti_debugging(raw)
        assert "Function(\"debugger\")" not in clean
        assert count >= 2
        assert "removed anti-debug ctor" in clean

    def test_beautify_javascript_indents_and_breaks(self):
        minified = "function test(){if(true){var a=1;return a;}}"
        beautified = js_deobfuscator.beautify_javascript(minified)
        assert "{\n" in beautified or "{\r\n" in beautified or "\n  " in beautified
        assert "var a=1;" in beautified


# --------------------------------------------------------------------------- #
# web_modifier tests
# --------------------------------------------------------------------------- #
class TestWebModifier:
    def test_generate_userscript_anti_debug(self):
        script = web_modifier.generate_userscript(
            domain="https://example.com",
            template="bypass-anti-debug"
        )
        assert "// ==UserScript==" in script
        assert "@match        *://example.com/*" in script
        assert "console.clear" in script
        assert "Function" in script

    def test_generate_userscript_hook_api(self):
        script = web_modifier.generate_userscript(
            domain="api.example.com",
            template="hook-api"
        )
        assert "window.fetch" in script
        assert "XMLHttpRequest.prototype.open" in script

    def test_generate_userscript_override_func(self):
        script = web_modifier.generate_userscript(
            domain="example.com",
            template="override-func",
            func_name="window.auth.isVip",
            return_val="true"
        )
        assert "window.auth.isVip" in script
        assert "return true" in script


# --------------------------------------------------------------------------- #
# auth_flow_tracer & sql_auth_auditor tests
# --------------------------------------------------------------------------- #
def _load_direct(rel_path: str, name: str):
    import importlib.util
    root = Path(__file__).resolve().parents[2]
    p = root / rel_path
    spec = importlib.util.spec_from_file_location(name, str(p))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


auth_flow_tracer = _load_direct("skills/web-reverse/scripts/auth_flow_tracer.py", "auth_flow_tracer")
sql_auth_auditor = _load_direct("skills/web-security-audit/scripts/sql_auth_auditor.py", "sql_auth_auditor")
idor_bola_auditor = _load_direct("skills/web-security-audit/scripts/idor_bola_auditor.py", "idor_bola_auditor")
rate_limit_audit = _load_direct("skills/web-security-audit/scripts/rate_limit_audit.py", "rate_limit_audit")


class TestAuthFlowTracer:
    def test_scan_javascript_auth_detects_crypto_and_headers(self, tmp_path):
        sample = """
        const crypt = new JSEncrypt();
        crypt.setPublicKey('MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC...');
        const p = crypt.encrypt('secret_pass');
        fetch('/api/login', {
            headers: { 'X-Signature': CryptoJS.HmacSHA256(p, 'k').toString() }
        });
        """
        f = tmp_path / "app.js"
        f.write_text(sample, encoding="utf-8")
        res = auth_flow_tracer.scan_javascript_auth(str(f))

        assert "RSA Encryption (JSEncrypt)" in res["detected_crypto"]
        assert any("X-Signature" in h for h in res["detected_headers"])

    def test_audit_jwt_token_flags_none_algorithm(self):
        # Header: {"alg":"none"}, Payload: {"user":"admin"}
        tok = "eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ."
        res = auth_flow_tracer.audit_jwt_token(tok)
        assert any("algoritma 'none'" in f for f in res["findings"])

    def test_generate_auth_replay_script_contains_curl_cffi(self):
        code = auth_flow_tracer.generate_auth_replay_script("https://example.com/api/login")
        assert "curl_cffi" in code
        assert "https://example.com/api/login" in code


class TestSqlAuthAuditor:
    def test_audit_file_content_detects_sqli_concatenation(self):
        code = '$query = "SELECT * FROM users WHERE username = \'" . $user . "\'"; $db->query($query);'
        res = sql_auth_auditor.audit_file_content(Path("LoginController.php"), code)
        assert len(res["sqli"]) > 0
        assert any("Concatenation" in item["rule"] for item in res["sqli"])

    def test_audit_file_content_detects_weak_hash(self):
        code = '$hashed = md5($password);'
        res = sql_auth_auditor.audit_file_content(Path("RegisterController.php"), code)
        assert len(res["hashing"]) > 0
        assert any(h["type"] == "WEAK" for h in res["hashing"])

    def test_audit_file_content_identifies_secure_hash(self):
        code = '$hashed = password_hash($password, PASSWORD_ARGON2ID);'
        res = sql_auth_auditor.audit_file_content(Path("RegisterController.php"), code)
        assert any(h["type"] == "SECURE" for h in res["hashing"])


class TestIdorBolaAuditor:
    def test_audit_idor_file_detects_unscoped_find(self):
        code = """
        class OrderController {
            public function show($id) {
                $order = Order::findOrFail($id);
                return response()->json($order);
            }
        }
        """
        findings = idor_bola_auditor.audit_idor_file(Path("OrderController.php"), code)
        assert len(findings) > 0
        assert any("BOLA" in item["rule"] for item in findings)

    def test_audit_idor_file_detects_express_find_by_id(self):
        code = """
        app.get('/api/orders/:id', async (req, res) => {
            const order = await Order.findById(req.params.id);
            res.json(order);
        });
        """
        findings = idor_bola_auditor.audit_idor_file(Path("order.js"), code)
        assert len(findings) > 0
        assert any("findById" in item["rule"] for item in findings)


class TestRateLimitAudit:
    def test_audit_route_content_detects_unprotected_login(self):
        code = """
        Route::post('/api/login', [AuthController::class, 'login']);
        Route::post('/api/register', [AuthController::class, 'register']);
        """
        findings = rate_limit_audit.audit_route_content(Path("api.php"), code)
        assert len(findings) == 2
        assert any(f["endpoint_type"] == "login" for f in findings)
        assert any(f["endpoint_type"] == "register" for f in findings)

    def test_audit_route_content_recognizes_throttle_middleware(self):
        code = """
        Route::post('/api/login', [AuthController::class, 'login'])->middleware('throttle:login');
        """
        findings = rate_limit_audit.audit_route_content(Path("api.php"), code)
        assert len(findings) == 0


