"""Configuración del puerto local y bootstrap HTTP simulado, sin proveedores."""

import importlib.util
import io
import os
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("local_proxy_setup", Path(__file__).with_name("setup.py"))
setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)


class LocalProxyPortTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.env_path = Path(temporary.name) / ".env"
        self.patch_env_path = patch.object(setup, "ENV_PATH", self.env_path)
        self.patch_env_path.start()
        self.addCleanup(self.patch_env_path.stop)
        self.patch_environment = patch.dict(os.environ, {}, clear=True)
        self.patch_environment.start()
        self.addCleanup(self.patch_environment.stop)

    def test_default_avoids_giskard_port(self):
        self.assertEqual(setup.local_proxy_url(), "http://127.0.0.1:4001")

    def test_existing_env_without_port_uses_new_default(self):
        self.env_path.write_text("AUDIT_MODEL=audit-test\n")
        self.assertEqual(setup.local_proxy_url(), "http://127.0.0.1:4001")

    def test_port_from_dotenv(self):
        self.env_path.write_text("LITELLM_PORT=4100\n")
        self.assertEqual(setup.local_proxy_url(), "http://127.0.0.1:4100")

    def test_shell_overrides_dotenv(self):
        self.env_path.write_text("LITELLM_PORT=4100\n")
        os.environ["LITELLM_PORT"] = "4200"
        self.assertEqual(setup.local_proxy_url(), "http://127.0.0.1:4200")

    def test_empty_shell_uses_default_like_compose(self):
        self.env_path.write_text("LITELLM_PORT=4100\n")
        os.environ["LITELLM_PORT"] = ""
        self.assertEqual(setup.local_proxy_url(), "http://127.0.0.1:4001")

    def test_invalid_port_fails_before_request(self):
        for port in ("abc", "0", "-1", "65536"):
            with self.subTest(port=port), patch.dict(os.environ, {"LITELLM_PORT": port}):
                with self.assertRaisesRegex(RuntimeError, "LITELLM_PORT"):
                    setup.local_proxy_url()

    def test_bootstrap_request_uses_configured_host_port(self):
        self.env_path.write_text("LITELLM_PORT=4300\n")
        with patch.object(setup.urllib.request, "urlopen",
                          return_value=closing(io.BytesIO(b'{"user_id": "test"}'))) as urlopen:
            result = setup.request("/user/info?user_id=test", "sk-test-only")
        self.assertEqual(result, {"user_id": "test"})
        self.assertEqual(urlopen.call_args.args[0].full_url,
                         "http://127.0.0.1:4300/user/info?user_id=test")


if __name__ == "__main__":
    unittest.main()
