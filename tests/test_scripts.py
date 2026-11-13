import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class InstallerScriptTests(unittest.TestCase):
    def test_uninstall_preserves_vault_and_removes_code(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            prefix = Path(tmp)
            vault = prefix / "share" / "shkatulka" / "vault.shk"
            vault.parent.mkdir(parents=True)
            vault.write_bytes(b"ENCRYPTED VAULT")

            lib_app = prefix / "lib" / "shkatulka" / "app" / "shkatulka"
            lib_app.mkdir(parents=True)
            (lib_app / "__init__.py").write_text("")

            legacy_app = prefix / "share" / "shkatulka" / "app"
            legacy_app.mkdir()

            bin_path = prefix / "bin" / "shkatulka"
            bin_path.parent.mkdir(parents=True)
            bin_path.write_text("")

            result = subprocess.run(
                ["sh", str(ROOT / "uninstall.sh")],
                input="y\n",
                text=True,
                capture_output=True,
                env={**os.environ, "PREFIX": str(prefix)},
                cwd=ROOT,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(vault.read_bytes(), b"ENCRYPTED VAULT")
            self.assertFalse(lib_app.exists())
            self.assertFalse(legacy_app.exists())
            self.assertIn("Сейф не тронут", result.stdout)

    def test_launchers_use_safe_python_path(self) -> None:
        run_sh = (ROOT / "run.sh").read_text()
        install_sh = (ROOT / "install.sh").read_text()
        self.assertIn("python3 -P -m shkatulka", run_sh)
        self.assertIn("python3 -P -m shkatulka", install_sh)
        self.assertIn("../lib/shkatulka/app", install_sh)
        self.assertNotIn("rm -rf \"$DEST\"", install_sh)


if __name__ == "__main__":
    unittest.main()
