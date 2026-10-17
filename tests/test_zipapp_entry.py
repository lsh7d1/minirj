"""Tests for the zipapp entry dispatcher."""
import importlib.util
from pathlib import Path
import os
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("zipapp_entry", ROOT / "deploy/zipapp_main.py")
entry = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(entry)


class DispatchTests(unittest.TestCase):
    def test_no_arguments_runs_service(self):
        with patch("minirj.service.main", return_value=7) as service_main:
            self.assertEqual(entry.dispatch([]), 7)
            service_main.assert_called_once_with([])

    def test_down_runs_service_down_mode(self):
        with patch("minirj.service.main", return_value=0) as service_main:
            self.assertEqual(entry.dispatch(["--down"]), 0)
            service_main.assert_called_once_with(["--down"])

    def test_interface_argument_runs_dhcp_hook(self):
        with patch.dict(os.environ, {"MINIRJ_INTERFACE": "campus0"}), \
                patch("minirj.service.main", return_value=0) as service_main:
            self.assertEqual(entry.dispatch(["campus0"]), 0)
            service_main.assert_called_once_with(["campus0"])

    def test_other_arguments_go_to_cli(self):
        with patch.dict(os.environ, {"MINIRJ_INTERFACE": "campus0"}), \
                patch("minirj.main.main", return_value=2) as cli_main:
            self.assertEqual(entry.dispatch(["--version"]), 2)
            cli_main.assert_called_once_with(["--version"])

    def test_unknown_single_argument_is_not_a_hook(self):
        with patch.dict(os.environ, {"MINIRJ_INTERFACE": "campus0"}), \
                patch("minirj.main.main", return_value=2) as cli_main:
            self.assertEqual(entry.dispatch(["other0"]), 2)
            cli_main.assert_called_once_with(["other0"])


if __name__ == "__main__":
    unittest.main()
