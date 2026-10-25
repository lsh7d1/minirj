"""Developer-only Bash control-flow tests. All host/network/service operations mocked.

Run the real shell script in a disposable directory, replacing only its fixed paths
and PATH with a private copy. No production test hooks, root, network, or systemd
are required. Python settings/credential validation still executes real Python.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "deploy.sh"

MOCK = r"""import fcntl,json,os,pathlib,signal,subprocess,sys
root=pathlib.Path(os.environ['MINIRJ_MOCK_ROOT'])
lock=(root/'mock-state.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX)
state_file=root/'state.json';s=json.loads(state_file.read_text())
name=pathlib.Path(sys.argv[0]).name;a=sys.argv[1:]
s.setdefault('calls',[]).append([name,*a])
def save():
 state_file.write_text(json.dumps(s));fcntl.flock(lock,fcntl.LOCK_UN)
def out(value='',code=0):
 save()
 if value:print(value)
 raise SystemExit(code)
def config():
 p=root/'etc/service.conf'
 return dict(l.split('=',1) for l in p.read_text().splitlines() if '=' in l) if p.exists() else {}
def stop():
 s.setdefault('stop_configs',[]).append(config().get('MINIRJ_NM_UUID',''))
 s['active']=False;s['active_uuid']=''
if name=='id':
 if len(a)==2:out(code=0 if s.get('user_created') else 1)
 out('0')
if name=='useradd':
 s['user_created']=True;out()
if name=='stat':
 p=pathlib.Path(a[-1]);out('0:'+oct(p.stat().st_mode&0o777)[2:])
if name=='curl':out('curl 8.14.1 (mock)')
if name=='flock':out(code=1 if s.get('locked') else 0)
if name=='systemd-analyze':out(code=1 if s.get('verify_fail') else 0)
if name=='systemd-ask-password':
 key='username' if 'username' in a[0] else 'password'
 if s.get('cancel')==key:out(code=1)
 value=s.get('new_'+key, 'synthetic-user' if key=='username' else ' synthetic-secret ')
 save();sys.stdout.write(value+'\n');raise SystemExit(0)
if name=='journalctl':out('health OK: HTTPS 200; phase 2 complete')
if name=='sleep':
 if s.get('restart_during_observation'):s['invocation']='different-invocation'
 if s.get('offline_during_observation'):s['active']=False
 if s.get('interrupt'):save();os.kill(os.getppid(),signal.SIGTERM);raise SystemExit(0)
 out()
if name=='ip':
 if 'route' in a:out(json.dumps([{'dev':s.get('ssh_interface','management0')}]))
 out(json.dumps([{'addr_info':[{'scope':'global'}] if s.get('global_address') else []}]))
if name=='nmcli':
 if a[:1]==['--wait']:a=a[2:]
 if a[:1]==['-g']:
  prop=a[1]
  if prop=='GENERAL.NM-MANAGED':out('no' if s.get('unmanaged') else 'yes')
  if prop=='GENERAL.CON-UUID':out(s.get('active_uuid',''))
  if prop=='connection.interface-name,connection.autoconnect,ipv4.method':
   profile=s.get('profiles',{}).get(a[-1]);out('\n'.join(profile) if profile else '',0 if profile else 1)
 if a[:2]==['connection','add']:
  uid=a[a.index('connection.uuid')+1];iface=a[a.index('ifname')+1]
  s.setdefault('profiles',{})[uid]=[iface,'no','auto']
  s.setdefault('profile_dns',{})[uid]={'ipv4.ignore-auto-dns':'no','ipv4.dns':'','ipv4.dns-options':''};out()
 if a[:2]==['connection','modify']:
  assert a[2:3]==['uuid'] and len(a[4:])%2==0, 'modify must use an explicit UUID and property/value pairs'
  uid=a[3]
  if uid not in s.get('profiles',{}):out(code=10)
  changes=dict(zip(a[4::2],a[5::2]))
  assert set(changes) <= {'ipv4.ignore-auto-dns','ipv4.dns','ipv4.dns-options','connection.permissions'}, 'unexpected profile modification'
  if 'connection.permissions' in changes:
   s.setdefault('permissions',{})[uid]=changes['connection.permissions']
  dns_changes={k:v for k,v in changes.items() if k!='connection.permissions'}
  if not dns_changes:out()
  s.setdefault('dns_modify_snapshots',[]).append({'uuid':uid,'config':config(),'active':s.get('active',False),
                                               'profile':s['profiles'][uid]})
  if s.get('dns_modify_fail'):out(code=1)
  s.setdefault('profile_dns',{}).setdefault(uid,{}).update(dns_changes)
  # Model a failure after persistence too: existing profile changes must not be implicitly rolled back.
  out(code=1 if s.get('dns_modify_partial_fail') else 0)
 if a[:2]==['connection','delete']:
  s.get('profiles',{}).pop(a[-1],None);s.get('profile_dns',{}).pop(a[-1],None);out()
 raise AssertionError('unmocked nmcli operation')
if name=='systemctl':
 if a[0]=='--version':out('systemd 257 (mock)')
 if a[0]=='show':
  if '--value' not in a:out('MainPID=0')
  prop=a[a.index('-p')+1]
  unit_exists=(root/'unit/minirj.service').exists()
  values={'FragmentPath':str(root/'unit/minirj.service') if unit_exists else '',
          'DropInPaths':s.get('dropins',''),'LoadState':'loaded' if unit_exists else 'not-found',
          'InvocationID':s.get('invocation','trial-invocation') if s.get('active') else '',
          'StatusText':s.get('status_text','Online; bound HTTPS check passed')}
  out(values[prop])
 if a[0]=='is-active':out(code=0 if a[-1]=='NetworkManager.service' or s.get('active') else 3)
 if a[0]=='is-enabled':out(code=0 if s.get('enabled') else 1)
 if a[0]=='stop':stop();out()
 if a[0]=='start':
  s.setdefault('start_configs',[]).append(config())
  if s.get('start_fail'):out(code=1)
  s['active']=True;s['active_uuid']=config()['MINIRJ_NM_UUID'];out()
 if a[0]=='enable':s['enabled']=True;out(code=1 if s.get('enable_fail') else 0)
 if a[0]=='disable':
  s['enabled']=False
  if '--now' in a:stop()
  out()
 if a[0]=='daemon-reload':out()
 if a[0]=='status':out('mock service state',0 if s.get('active') else 3)
 raise AssertionError('unmocked systemctl operation')
if name=='mv':
 if s.get('config_write_fail') and a[-1].endswith('/service.conf'):out(code=1)
 save();os.execv('/usr/bin/mv',['mv',*a])
if name in ('python','python3'):
 if any(str(x).endswith('deploy/build_zipapp.py') for x in a):
  target=pathlib.Path(a[a.index('--output')+1]);target.parent.mkdir(parents=True,exist_ok=True)
  target.write_text('mock zipapp');out('mock zipapp built')
 if any(str(x).endswith('minirj.pyz') for x in a) and '--version' in a:out('minirj 1.0.0', 1 if s.get('pip_fail') else 0)
 if '-m' in a:
  module=a[a.index('-m')+1]
  if module=='zipfile':
   pathlib.Path(a[-1]).mkdir(parents=True,exist_ok=True);out()
  if module=='unittest':out('mock optional test invocation')
 save();os.execv(os.environ['MINIRJ_REAL_PYTHON'],[os.environ['MINIRJ_REAL_PYTHON'],*a])
raise AssertionError('unmocked command')
"""


class DeployScriptTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.kit = self.base / "delivery with spaces"
        self.kit.mkdir()
        (self.kit / "deploy/systemd").mkdir(parents=True)
        for name in ("minirj.service", "50-minirj.rules"):
            shutil.copy2(ROOT / "deploy/systemd" / name, self.kit / "deploy/systemd" / name)
        (self.kit / "deploy/network-manager").mkdir(parents=True)
        shutil.copy2(ROOT / "deploy/network-manager" / "90-minirj-dhcp-policy",
                     self.kit / "deploy/network-manager" / "90-minirj-dhcp-policy")
        for name in ("build_zipapp.py", "zipapp_main.py"):
            shutil.copy2(ROOT / "deploy" / name, self.kit / "deploy" / name)
        (self.kit / "tests").mkdir()
        for name in ("bin", "unit", "elsewhere", "polkit"):
            (self.base / name).mkdir()
        self.script = self.kit / "deploy.sh"
        text = SCRIPT.read_text()
        replacements = {
            "export PATH=/usr/sbin:/usr/bin:/sbin:/bin": f'export PATH="{self.base}/bin:/usr/sbin:/usr/bin:/sbin:/bin"',
            "INSTALL_DIR=/opt/minirj": f'INSTALL_DIR="{self.base}/opt"',
            "CONFIG_DIR=/etc/minirj": f'CONFIG_DIR="{self.base}/etc"',
            "UNIT_FILE=/etc/systemd/system/minirj.service": f'UNIT_FILE="{self.base}/unit/minirj.service"',
            "LOCK_FILE=/run/minirj-deploy.lock": f'LOCK_FILE="{self.base}/lock"',
            "PYTHON=/usr/bin/python3": f'PYTHON="{self.base}/bin/python3"',
            "POLKIT_RULE=/etc/polkit-1/rules.d/50-minirj.rules": f'POLKIT_RULE="{self.base}/polkit/50-minirj.rules"',
            "DISPATCHER_SCRIPT=/etc/NetworkManager/dispatcher.d/90-minirj-dhcp-policy":
                f'DISPATCHER_SCRIPT="{self.base}/dispatcher/90-minirj-dhcp-policy"',
            "[[ -d /etc/polkit-1/rules.d ]]": f'[[ -d "{self.base}/polkit" ]]',
        }
        for old, new in replacements.items():
            self.assertEqual(text.count(old), 1)
            text = text.replace(old, new)
        self.script.write_text(text)
        self.mock = self.base / "mock.py"
        self.mock.write_text(f"#!{sys.executable}\n" + MOCK)
        self.mock.chmod(0o755)
        for name in ("id", "useradd", "stat", "flock", "systemd-analyze", "systemd-ask-password",
                     "journalctl", "sleep", "ip", "nmcli", "systemctl", "python3", "mv"):
            (self.base / "bin" / name).symlink_to(self.mock)
        self.env = {k: v for k, v in os.environ.items()
                    if k not in ("SSH_CONNECTION", "SSH_CLIENT", "BASH_ENV", "ENV")}
        self.env.update(MINIRJ_MOCK_ROOT=str(self.base), MINIRJ_REAL_PYTHON=sys.executable)
        self.write_state({})
        (self.kit / "minirj").mkdir()
        (self.kit / "minirj/main.py").write_text("# mock\n")

    def state(self):
        return json.loads((self.base / "state.json").read_text())

    def write_state(self, state):
        (self.base / "state.json").write_text(json.dumps(state))

    def modify(self, **changes):
        state = self.state()
        state.update(changes)
        self.write_state(state)

    def run_script(self, *args, success=True, trace=False):
        result = subprocess.run(["bash", *(["-x"] if trace else []), str(self.script), *args],
                                cwd=self.base / "elsewhere", env=self.env, text=True,
                                capture_output=True, timeout=20)
        if success:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0)
        return result

    def install(self):
        return self.run_script("install", "--interface", "campus0")

    def calls(self, name=None):
        calls = self.state().get("calls", [])
        return [c for c in calls if name is None or c[0] == name]

    def config(self):
        path = self.base / "etc/service.conf"
        return dict(line.split("=", 1) for line in path.read_text().splitlines()) if path.exists() else {}

    def dns_calls(self):
        return [call for call in self.calls("nmcli")
                if call[3:5] == ["connection", "modify"] and "ipv4.dns" in call]

    def assert_dns_profile(self, uuid, servers=None):
        self.assertEqual(self.state()["profile_dns"][uuid], {
            "ipv4.ignore-auto-dns": "yes" if servers is not None else "no",
            "ipv4.dns": servers if servers is not None else "",
            "ipv4.dns-options": "timeout:1,attempts:2" if servers is not None else "",
        })

    def assert_dns_lifecycle(self, old_config, uuid):
        calls = self.calls()
        self.assertEqual(len(self.dns_calls()), 1)
        stop = calls.index(["systemctl", "stop", "minirj.service"])
        modify = calls.index(self.dns_calls()[0])
        commit = next(i for i, call in enumerate(calls)
                      if call[0] == "mv" and call[-1] == str(self.base / "etc/service.conf"))
        start = calls.index(["systemctl", "start", "minirj.service"])
        self.assertLess(stop, modify)
        self.assertLess(modify, commit)
        self.assertLess(commit, start)
        self.assertIn(["nmcli", "--wait", "15", "-g",
                       "connection.interface-name,connection.autoconnect,ipv4.method",
                       "connection", "show", "uuid", uuid], calls[stop + 1:modify])
        self.assertEqual(self.state()["stop_configs"][0], old_config["MINIRJ_NM_UUID"])
        self.assertEqual(self.state()["dns_modify_snapshots"], [{
            "uuid": uuid, "config": old_config, "active": False,
            "profile": self.state()["profiles"][uuid],
        }])
        self.assertEqual(self.state()["start_configs"][-1], self.config())
        self.assertFalse(any("up" in call for call in self.calls("nmcli")))

    def assert_no_mutation(self):
        self.assertFalse((self.base / "opt").exists())
        self.assertFalse((self.base / "etc").exists())
        self.assertFalse(self.state().get("profiles"))
        self.assertFalse(any(c[1:2] in (["start"], ["stop"], ["enable"]) for c in self.calls("systemctl")))

    def test_help_unknown_options_and_credential_arguments_never_mutate(self):
        self.run_script("--help")
        for args in (("bad-action",), ("install", "--interface"), ("install", "--password", "do-not-use")):
            self.run_script(*args, success=False)
        self.assert_no_mutation()

    def test_install_from_any_cwd_and_enable_only_after_observation(self):
        self.install()
        state = self.state()
        self.assertTrue(state["active"] and state["enabled"])
        self.assertEqual(len(state["profiles"]), 1)
        calls = self.calls()
        self.assertLess(calls.index(["sleep", "70"]), calls.index(["systemctl", "enable", "minirj.service"]))
        self.assertFalse(any("unittest" in c for c in calls))
        self.assertFalse(any("up" in c for c in self.calls("nmcli")))

    def test_install_and_no_enable(self):
        self.run_script("install", "--interface", "campus0", "--no-enable")
        self.assertTrue(self.state()["active"])
        self.assertFalse(self.state().get("enabled", False))

    def test_missing_source_and_interface_fail_before_mutation(self):
        self.run_script("install", success=False)
        shutil.rmtree(self.kit / "minirj")
        self.run_script("install", "--interface", "campus0", success=False)
        self.assert_no_mutation()

    def test_management_interface_or_foreign_connection_is_rejected(self):
        for changes in ({"active_uuid": "someone-else"}, {"global_address": True}, {"unmanaged": True}, {"ssh_interface": "campus0"}):
            with self.subTest(changes=changes):
                self.write_state(changes)
                self.env["SSH_CONNECTION"] = "192.0.2.1 2222 192.0.2.2 22"
                self.run_script("install", "--interface", "campus0", success=False)
                self.assert_no_mutation()

    def test_uses_real_nmcli_managed_field(self):
        self.install()
        self.assertIn(["nmcli", "--wait", "15", "-g", "GENERAL.NM-MANAGED",
                       "device", "show", "campus0"], self.calls("nmcli"))
        self.assertFalse(any("GENERAL.MANAGED" in call for call in self.calls("nmcli")))

    def test_reinstall_preserves_credentials_and_reuses_only_valid_profile(self):
        self.install()
        config = (self.base / "etc/service.conf").read_bytes()
        credentials = [(self.base / "etc" / n).read_bytes() for n in ("username", "password")]
        self.modify(calls=[], new_password="must-not-be-used")
        self.run_script("install")
        self.assertEqual((self.base / "etc/service.conf").read_bytes(), config)
        self.assertEqual([(self.base / "etc" / n).read_bytes() for n in ("username", "password")], credentials)
        self.assertEqual(len(self.state()["profiles"]), 1)
        self.assertFalse(self.calls("systemd-ask-password"))
        state = self.state()
        next(iter(state["profiles"].values()))[1] = "yes"
        self.write_state(state)
        self.run_script("install", success=False)
        self.assertTrue(self.state()["active"])

    def test_runtime_binary_and_credentials_permissions(self):
        self.install()
        pyz = self.base / "opt/minirj.pyz"
        self.assertTrue(pyz.is_file())
        self.assertEqual(pyz.stat().st_mode & 0o111, 0o111)
        self.assertEqual((self.base / "etc").stat().st_mode & 0o777, 0o700)
        for name in ("service.conf", "username", "password"):
            self.assertEqual((self.base / "etc" / name).stat().st_mode & 0o777, 0o600)

    def test_startup_failure_restart_or_loss_of_ready_stops_without_enable(self):
        for scenario in ("start_fail", "restart_during_observation", "offline_during_observation", "enable_fail", "interrupt"):
            with self.subTest(scenario=scenario):
                self.modify(**{scenario: True}, enabled=False, calls=[])
                self.run_script("install", "--interface", "campus0", success=False)
                self.assertFalse(self.state().get("active", False))
                self.assertFalse(self.state().get("enabled", False))
                self.modify(**{scenario: False})

    def test_missing_invocation_or_ready_status_is_failure(self):
        for values in ({"invocation": ""}, {"invocation": "trial", "status_text": "not ready"}):
            with self.subTest(values=values):
                self.modify(**values)
                self.run_script("install", "--interface", "campus0", success=False)
                self.assertFalse(self.state().get("active", False))
                self.assertFalse(self.state().get("enabled", False))

    def test_credentials_cancellation_or_invalid_input_preserves_old_values(self):
        self.install()
        old = [(self.base / "etc" / n).read_bytes() for n in ("username", "password")]
        for values in ({"cancel": "password"}, {"cancel": "", "new_password": ""},
                       {"new_password": "bad\nline"}, {"new_password": "bad\0value"}):
            with self.subTest(values=values):
                self.modify(**values)
                self.run_script("credentials", success=False)
                self.assertEqual([(self.base / "etc" / n).read_bytes() for n in ("username", "password")], old)
                self.assertFalse(self.state()["active"])
                self.assertFalse(list((self.base / "etc").glob(".credentials.*")))

    def test_credentials_use_protected_files_and_do_not_echo_even_with_xtrace(self):
        self.install()
        self.modify(new_password=" replacement-synthetic-secret ", calls=[])
        result = self.run_script("credentials", trace=True)
        self.assertEqual((self.base / "etc/password").read_text(), " replacement-synthetic-secret \n")
        self.assertEqual((self.base / "etc/password").stat().st_mode & 0o777, 0o600)
        self.assertNotIn("replacement-synthetic-secret", result.stdout + result.stderr + json.dumps(self.calls()))
        self.assertTrue(self.state()["active"])

    def test_configuration_stops_with_old_uuid_before_changing_interface(self):
        self.install()
        old_uuid = next(iter(self.state()["profiles"]))
        self.modify(active_uuid="", calls=[], stop_configs=[])
        self.run_script("configure", "--interface", "other0", "--probe-url", "https://example.com/")
        self.assertEqual(self.state()["stop_configs"][0], old_uuid)
        self.assertEqual(len(self.state()["profiles"]), 2)
        text = (self.base / "etc/service.conf").read_text()
        self.assertIn("MINIRJ_INTERFACE=other0", text)
        self.assertIn("MINIRJ_PROBE_URL=https://example.com/", text)

    def test_install_refuses_interface_change_and_url_with_embedded_credentials(self):
        self.run_script("install", "--interface", "campus0", "--probe-url", "https://user:secret@example.com/", success=False)
        self.assert_no_mutation()
        self.install()
        self.modify(calls=[])
        self.run_script("install", "--interface", "other0", success=False)
        self.assertTrue(self.state()["active"])
        self.assertNotIn(["systemctl", "stop", "minirj.service"], self.calls())

    def test_config_is_data_not_sourced_shell(self):
        self.install()
        marker = self.base / "must-not-exist"
        with (self.base / "etc/service.conf").open("a") as f:
            f.write('BAD[$(touch "' + str(marker) + '")]=anything\n')
        self.run_script("start", success=False)
        self.assertFalse(marker.exists())

    def test_uncommitted_profile_is_removed_if_config_write_fails(self):
        self.modify(config_write_fail=True)
        self.run_script("install", "--interface", "campus0", success=False)
        self.assertFalse(self.state()["profiles"])
        self.assertFalse(self.state().get("active", False))
        self.assertFalse(list((self.base / "etc").glob(".service.conf.*")))

    def test_failed_upgrade_preserves_profile_credentials_and_enablement(self):
        self.install()
        old_config = (self.base / "etc/service.conf").read_bytes()
        old_password = (self.base / "etc/password").read_bytes()
        self.modify(pip_fail=True, calls=[])
        self.run_script("upgrade", success=False)
        self.assertEqual((self.base / "etc/service.conf").read_bytes(), old_config)
        self.assertEqual((self.base / "etc/password").read_bytes(), old_password)
        self.assertEqual(len(self.state()["profiles"]), 1)
        self.assertFalse(self.state()["active"])
        self.assertTrue(self.state()["enabled"])

    def test_start_and_maintenance_do_not_install_or_run_tests(self):
        self.install()
        self.run_script("stop")
        self.modify(calls=[])
        self.run_script("start")
        self.run_script("enable")
        self.run_script("status")
        self.run_script("logs")
        self.assertFalse(any("pip" in c or "venv" in c or "unittest" in c for c in self.calls()))
        self.run_script("disable")
        self.assertFalse(self.state()["active"] or self.state()["enabled"])

    def test_optional_tests_extract_the_zipapp_and_run_tests(self):
        self.install()
        self.modify(calls=[])
        self.run_script("test")
        calls = self.calls()
        self.assertEqual([call[:4] for call in calls],
                         [["python3", "-I", "-m", "zipfile"],
                          ["python3", "-m", "unittest", "discover"]])
        self.assertEqual(calls[1][4:], ["-s", str(self.kit / "tests")])

    def test_lock_and_extra_unit_overrides_refuse_mutation(self):
        for values in ({"locked": True}, {"dropins": "/etc/systemd/system/example.conf"}):
            with self.subTest(values=values):
                self.write_state(values)
                self.run_script("install", "--interface", "campus0", success=False)
                self.assert_no_mutation()

    def test_dns_default_is_opt_in_and_help_documents_interface_change(self):
        help_text = self.run_script("--help").stdout
        for text in ("--dns SERVERS", "--dns-auto", "1..3", "timeout:1,attempts:2",
                     "install/configure", "install/upgrade/start/restart", "更换接口", "DHCP"):
            self.assertIn(text, help_text)
        self.assert_no_mutation()
        self.install()
        uuid = self.config()["MINIRJ_NM_UUID"]
        self.assert_dns_profile(uuid)
        self.assertFalse(self.dns_calls())
        add = next(call for call in self.calls("nmcli") if "add" in call)
        for prop in ("ipv4.ignore-auto-dns", "ipv4.dns", "ipv4.dns-options"):
            self.assertNotIn(prop, add)
        self.assertEqual(set(self.config()), {"MINIRJ_INTERFACE", "MINIRJ_NM_UUID", "MINIRJ_PROBE_URL"})
        self.assertFalse(any("up" in call for call in self.calls("nmcli")))

    def test_dns_canonicalizes_one_to_three_distinct_unicast_servers(self):
        cases = (
            ("10.0.0.53", "10.0.0.53"),
            (" 172.16.0.53, 192.168.1.53 ", "172.16.0.53 192.168.1.53"),
            ("10.0.0.53 10.0.0.54", "10.0.0.53 10.0.0.54"),
            ("10.0.0.53,\t172.31.255.53 192.168.255.53", "10.0.0.53 172.31.255.53 192.168.255.53"),
            ("1.1.1.1,8.8.8.8", "1.1.1.1 8.8.8.8"),
        )
        for index, (value, canonical) in enumerate(cases):
            with self.subTest(value=value):
                self.modify(calls=[], dns_modify_snapshots=[])
                action = "install" if index % 2 == 0 else "configure"
                args = ("--interface", "campus0") if index == 0 else ()
                self.run_script(action, *args, "--dns", value)
                uuid = self.config()["MINIRJ_NM_UUID"]
                self.assert_dns_profile(uuid, canonical)
                self.assertEqual(self.dns_calls(), [[
                    "nmcli", "--wait", "15", "connection", "modify", "uuid", uuid,
                    "ipv4.ignore-auto-dns", "yes", "ipv4.dns", canonical,
                    "ipv4.dns-options", "timeout:1,attempts:2",
                ]])
                self.assertFalse(self.state()["dns_modify_snapshots"][0]["active"])
                self.assertFalse(any("up" in call for call in self.calls("nmcli")))

    def test_dns_invalid_values_fail_before_stop_or_profile_mutation(self):
        self.run_script("install", "--interface", "campus0", "--dns", "10.0.0.53")
        old_config = (self.base / "etc/service.conf").read_bytes()
        old_profiles = self.state()["profiles"]
        old_dns = self.state()["profile_dns"]
        values = (
            "", " ", "\t\n", "0.0.0.0", "0.0.0.53", "0.255.255.255",
            "127.0.0.1", "127.255.1.53", "169.254.0.1", "169.254.255.254",
            "224.0.0.1", "239.255.255.255", "240.0.0.1", "250.0.0.53", "255.255.255.255",
            "::1", "2001:db8::53", "dns.example.com", "256.0.0.1", "10.1.2", "010.0.0.53",
            "10.0.0.53/24", "10.0.0.53:53", "10.0.0.53;touch must-not-exist", "--dns-auto",
            ",10.0.0.53", "10.0.0.53,", "10.0.0.53,,10.0.0.54", "10.0.0.53, ,10.0.0.54",
            "10.0.0.53,10.0.0.53", "10.0.0.53 10.0.0.53",
            "10.0.0.53,10.0.0.54,10.0.0.55,10.0.0.56", "10.0.0.53,127.0.0.1",
        )
        for action in ("install", "configure"):
            for value in values:
                with self.subTest(action=action, value=value):
                    self.modify(calls=[])
                    self.run_script(action, "--dns", value, success=False)
                    self.assertFalse(self.calls("systemctl"))
                    self.assertFalse(self.calls("nmcli"))
                    self.assertTrue(self.state()["active"])
                    self.assertEqual(self.state()["profiles"], old_profiles)
                    self.assertEqual(self.state()["profile_dns"], old_dns)
                    self.assertEqual((self.base / "etc/service.conf").read_bytes(), old_config)
                    self.assertFalse((self.base / "elsewhere/must-not-exist").exists())

    def test_dns_missing_repeated_or_conflicting_options_fail_before_mutation(self):
        self.install()
        old_config = (self.base / "etc/service.conf").read_bytes()
        old_dns = self.state()["profile_dns"]
        options = (
            ("--dns",), ("--dns-auto", "--dns-auto"),
            ("--dns", "10.0.0.53", "--dns", "10.0.0.53"),
            ("--dns", "10.0.0.53", "--dns", "10.0.0.54"),
            ("--dns", "10.0.0.53", "--dns-auto"),
            ("--dns-auto", "--dns", "10.0.0.53"),
            ("--dns-auto", "10.0.0.53"),
        )
        for action in ("install", "configure"):
            for args in options:
                with self.subTest(action=action, args=args):
                    self.modify(calls=[])
                    self.run_script(action, *args, success=False)
                    self.assertFalse(self.calls())
                    self.assertTrue(self.state()["active"])
                    self.assertEqual(self.state()["profile_dns"], old_dns)
                    self.assertEqual((self.base / "etc/service.conf").read_bytes(), old_config)

    def test_dns_options_are_rejected_for_all_other_actions_before_operations(self):
        self.install()
        old_config = (self.base / "etc/service.conf").read_bytes()
        old_dns = self.state()["profile_dns"]
        for action in ("upgrade", "credentials", "start", "restart", "stop", "enable", "disable",
                       "status", "logs", "test"):
            for options in (("--dns", "10.0.0.53"), ("--dns-auto",)):
                with self.subTest(action=action, options=options):
                    self.modify(calls=[])
                    self.run_script(action, *options, success=False)
                    self.assertFalse(self.calls())
                    self.assertTrue(self.state()["active"] and self.state()["enabled"])
                    self.assertEqual(self.state()["profile_dns"], old_dns)
                    self.assertEqual((self.base / "etc/service.conf").read_bytes(), old_config)

    def test_dns_manual_request_targets_own_uuid_after_old_stop_before_commit(self):
        self.install()
        old_config = self.config()
        uuid = old_config["MINIRJ_NM_UUID"]
        foreign_uuid = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
        foreign_dns = {"ipv4.ignore-auto-dns": "yes", "ipv4.dns": "10.99.0.53", "ipv4.dns-options": "rotate"}
        state = self.state()
        state["profiles"][foreign_uuid] = ["management0", "yes", "manual"]
        state["profile_dns"][foreign_uuid] = foreign_dns
        self.write_state(state)
        self.modify(calls=[], stop_configs=[], dns_modify_snapshots=[], start_configs=[])
        self.run_script("configure", "--dns", "10.0.0.53,10.0.0.54", "--probe-url", "https://example.com/")
        self.assert_dns_profile(uuid, "10.0.0.53 10.0.0.54")
        self.assertEqual(self.dns_calls()[0][5:7], ["uuid", uuid])
        self.assertEqual(self.state()["profile_dns"][foreign_uuid], foreign_dns)
        self.assertEqual(self.state()["profiles"][foreign_uuid], ["management0", "yes", "manual"])
        self.assertEqual(self.config(), {"MINIRJ_INTERFACE": "campus0", "MINIRJ_NM_UUID": uuid,
                                         "MINIRJ_PROBE_URL": "https://example.com/",
                                         "MINIRJ_EXTERNAL_DNS": "10.0.0.53 10.0.0.54"})
        self.assert_dns_lifecycle(old_config, uuid)

    def test_dns_interface_change_defaults_to_dhcp_and_preserves_old_profile_dns(self):
        self.run_script("install", "--interface", "campus0", "--dns", "10.0.0.53")
        old_uuid = self.config()["MINIRJ_NM_UUID"]
        old_dns = self.state()["profile_dns"][old_uuid]
        self.modify(active_uuid="", calls=[], stop_configs=[])
        self.run_script("configure", "--interface", "other0")
        new_uuid = self.config()["MINIRJ_NM_UUID"]
        self.assertNotEqual(new_uuid, old_uuid)
        self.assert_dns_profile(new_uuid)
        self.assertEqual(self.state()["profile_dns"][old_uuid], old_dns)
        self.assertEqual(self.state()["stop_configs"][0], old_uuid)
        self.assertFalse(self.dns_calls())
        self.assertEqual(len(self.state()["profiles"]), 2)

    def test_dns_interface_change_explicit_request_updates_only_new_uuid(self):
        self.run_script("install", "--interface", "campus0", "--dns", "10.0.0.53")
        old_config = self.config()
        old_uuid = old_config["MINIRJ_NM_UUID"]
        old_dns = self.state()["profile_dns"][old_uuid]
        self.modify(active_uuid="", calls=[], stop_configs=[], dns_modify_snapshots=[], start_configs=[])
        self.run_script("configure", "--interface", "other0", "--dns", "192.168.1.53 172.16.0.53")
        new_uuid = self.config()["MINIRJ_NM_UUID"]
        self.assertNotEqual(new_uuid, old_uuid)
        self.assert_dns_profile(new_uuid, "192.168.1.53 172.16.0.53")
        self.assertEqual(self.state()["profile_dns"][old_uuid], old_dns)
        self.assertEqual(self.dns_calls()[0][5:7], ["uuid", new_uuid])
        self.assert_dns_lifecycle(old_config, new_uuid)
        calls = self.calls()
        add = next(i for i, call in enumerate(calls) if call[0] == "nmcli" and "add" in call)
        self.assertLess(calls.index(["systemctl", "stop", "minirj.service"]), add)
        self.assertLess(add, calls.index(self.dns_calls()[0]))

    def test_dns_auto_clears_manual_servers_and_options_in_stopped_lifecycle(self):
        self.run_script("install", "--interface", "campus0", "--dns", "10.0.0.53,10.0.0.54")
        old_config = self.config()
        uuid = old_config["MINIRJ_NM_UUID"]
        self.modify(calls=[], stop_configs=[], dns_modify_snapshots=[], start_configs=[])
        self.run_script("configure", "--dns-auto", "--probe-url", "https://example.com/")
        self.assert_dns_profile(uuid)
        self.assertEqual(self.dns_calls(), [[
            "nmcli", "--wait", "15", "connection", "modify", "uuid", uuid,
            "ipv4.ignore-auto-dns", "no", "ipv4.dns", "", "ipv4.dns-options", "",
        ]])
        self.assert_dns_lifecycle(old_config, uuid)

    def test_dns_auto_is_accepted_for_install_and_explicitly_applies_to_new_profile(self):
        self.run_script("install", "--interface", "campus0", "--dns-auto")
        uuid = self.config()["MINIRJ_NM_UUID"]
        self.assert_dns_profile(uuid)
        self.assertEqual(len(self.dns_calls()), 1)
        self.assertEqual(self.dns_calls()[0][5:7], ["uuid", uuid])
        self.assertEqual(self.state()["dns_modify_snapshots"][0]["config"], {})
        self.assertFalse(self.state()["dns_modify_snapshots"][0]["active"])
        self.assertFalse(any("up" in call for call in self.calls("nmcli")))

    def test_dns_no_options_preserve_existing_settings_across_upgrade_and_maintenance(self):
        self.run_script("install", "--interface", "campus0", "--dns", "10.0.0.53 192.168.1.53")
        uuid = self.config()["MINIRJ_NM_UUID"]
        state = self.state()
        state["profile_dns"][uuid]["ipv4.dns-options"] = "rotate,timeout:5,attempts:4"
        self.write_state(state)
        old_dns = self.state()["profile_dns"]
        old_profiles = self.state()["profiles"]
        for action in ("install", "upgrade", "configure", "start", "restart"):
            with self.subTest(action=action):
                self.modify(calls=[], dns_modify_snapshots=[])
                self.run_script(action)
                self.assertFalse(self.dns_calls())
                self.assertFalse(self.state()["dns_modify_snapshots"])
                self.assertEqual(self.state()["profile_dns"], old_dns)
                self.assertEqual(self.state()["profiles"], old_profiles)
                self.assertEqual(self.config()["MINIRJ_NM_UUID"], uuid)
                self.assertEqual(set(self.config()), {"MINIRJ_INTERFACE", "MINIRJ_NM_UUID", "MINIRJ_PROBE_URL", "MINIRJ_EXTERNAL_DNS"})

    def test_dns_requests_reject_foreign_and_ssh_management_interfaces_before_stop(self):
        scenarios = (
            {"active_uuid": "someone-else"}, {"active_uuid": "", "global_address": True},
            {"unmanaged": True}, {"ssh_interface": "campus0"},
        )
        self.env["SSH_CONNECTION"] = "192.0.2.1 2222 192.0.2.2 22"
        for changes in scenarios:
            for options in (("--dns", "10.0.0.53"), ("--dns-auto",)):
                with self.subTest(action="fresh install", changes=changes, options=options):
                    self.write_state(changes)
                    self.run_script("install", "--interface", "campus0", *options, success=False)
                    self.assert_no_mutation()
                    self.assertFalse(self.dns_calls())
        self.write_state({})
        self.env.pop("SSH_CONNECTION")
        self.install()
        baseline = self.state()
        old_config = (self.base / "etc/service.conf").read_bytes()
        self.env["SSH_CONNECTION"] = "192.0.2.1 2222 192.0.2.2 22"
        for changes in scenarios:
            for options in (("--dns", "10.0.0.53"), ("--dns-auto",)):
                with self.subTest(action="configure", changes=changes, options=options):
                    self.write_state({**baseline, **changes, "calls": []})
                    self.run_script("configure", *options, success=False)
                    self.assertFalse(self.dns_calls())
                    self.assertFalse(any(call[1] in ("stop", "start", "enable", "disable", "daemon-reload")
                                         for call in self.calls("systemctl")))
                    self.assertTrue(self.state()["active"])
                    self.assertEqual(self.state()["profiles"], baseline["profiles"])
                    self.assertEqual(self.state()["profile_dns"], baseline["profile_dns"])
                    self.assertEqual((self.base / "etc/service.conf").read_bytes(), old_config)

    def test_dns_requests_reject_non_dedicated_reused_profiles_before_stop(self):
        self.install()
        baseline = self.state()
        uuid = self.config()["MINIRJ_NM_UUID"]
        old_config = (self.base / "etc/service.conf").read_bytes()
        for profile in (["campus0", "yes", "auto"], ["campus0", "no", "manual"], ["other0", "no", "auto"]):
            for action in ("install", "configure"):
                for options in (("--dns", "10.0.0.53"), ("--dns-auto",)):
                    with self.subTest(profile=profile, action=action, options=options):
                        self.write_state({**baseline, "profiles": {uuid: profile}, "calls": []})
                        self.run_script(action, *options, success=False)
                        self.assertFalse(self.dns_calls())
                        self.assertNotIn(["systemctl", "stop", "minirj.service"], self.calls())
                        self.assertTrue(self.state()["active"])
                        self.assertEqual(self.state()["profiles"], {uuid: profile})
                        self.assertEqual(self.state()["profile_dns"], baseline["profile_dns"])
                        self.assertEqual((self.base / "etc/service.conf").read_bytes(), old_config)

    def test_dns_failed_modify_existing_profile_does_not_commit_start_or_roll_back(self):
        self.run_script("install", "--interface", "campus0", "--dns", "10.0.0.53")
        baseline = self.state()
        old_config = (self.base / "etc/service.conf").read_bytes()
        uuid = self.config()["MINIRJ_NM_UUID"]
        for failure in ("dns_modify_fail", "dns_modify_partial_fail"):
            for options, servers in ((("--dns", "10.0.0.54"), "10.0.0.54"), (("--dns-auto",), None)):
                with self.subTest(failure=failure, options=options):
                    self.write_state({**baseline, failure: True, "calls": [], "stop_configs": [],
                                      "dns_modify_snapshots": [], "start_configs": []})
                    result = self.run_script("configure", *options, "--probe-url", "https://example.com/", success=False)
                    self.assertFalse(self.state()["active"])
                    self.assertTrue(self.state()["enabled"])
                    self.assertEqual(self.state()["profiles"], baseline["profiles"])
                    self.assertEqual((self.base / "etc/service.conf").read_bytes(), old_config)
                    self.assertEqual(self.state()["stop_configs"][0], uuid)
                    self.assertEqual(self.state()["dns_modify_snapshots"][0]["config"], self.config())
                    self.assertFalse(self.state()["dns_modify_snapshots"][0]["active"])
                    self.assertEqual(len(self.dns_calls()), 1)
                    self.assertFalse(self.state()["start_configs"])
                    self.assertFalse(self.calls("mv"))
                    self.assertFalse(any("delete" in call for call in self.calls("nmcli")))
                    self.assertIn("未自动回退", result.stderr)
                    self.assertIn("DNS", result.stderr)
                    if failure == "dns_modify_partial_fail":
                        self.assert_dns_profile(uuid, servers)
                    else:
                        self.assertEqual(self.state()["profile_dns"], baseline["profile_dns"])

    def test_dns_failed_modify_new_profile_cleans_up_without_config_commit_or_start(self):
        for failure in ("dns_modify_fail", "dns_modify_partial_fail"):
            for options in (("--dns", "10.0.0.53"), ("--dns-auto",)):
                with self.subTest(failure=failure, options=options):
                    self.write_state({failure: True})
                    self.run_script("install", "--interface", "campus0", *options, success=False)
                    state = self.state()
                    new_uuid = state["dns_modify_snapshots"][0]["uuid"]
                    self.assertFalse(state["active"])
                    self.assertFalse(state["profiles"])
                    self.assertFalse(state["profile_dns"])
                    self.assertFalse((self.base / "etc/service.conf").exists())
                    self.assertFalse(state.get("start_configs"))
                    self.assertFalse(self.calls("mv"))
                    self.assertIn(["nmcli", "--wait", "15", "connection", "delete", "uuid", new_uuid], self.calls())
                    self.assertNotIn(["systemctl", "start", "minirj.service"], self.calls())
                    self.assertNotIn(["systemctl", "enable", "minirj.service"], self.calls())

    def test_dns_failed_interface_change_removes_only_uncommitted_new_profile(self):
        self.run_script("install", "--interface", "campus0", "--dns", "10.0.0.53")
        baseline = self.state()
        old_config = (self.base / "etc/service.conf").read_bytes()
        old_uuid = self.config()["MINIRJ_NM_UUID"]
        for failure in ("dns_modify_fail", "dns_modify_partial_fail"):
            for options in (("--dns", "192.168.1.53"), ("--dns-auto",)):
                with self.subTest(failure=failure, options=options):
                    self.write_state({**baseline, failure: True, "active_uuid": "", "calls": [],
                                      "stop_configs": [], "dns_modify_snapshots": [], "start_configs": []})
                    self.run_script("configure", "--interface", "other0", *options, success=False)
                    state = self.state()
                    new_uuid = state["dns_modify_snapshots"][0]["uuid"]
                    self.assertNotEqual(new_uuid, old_uuid)
                    self.assertEqual(state["stop_configs"][0], old_uuid)
                    self.assertEqual(state["profiles"], baseline["profiles"])
                    self.assertEqual(state["profile_dns"], baseline["profile_dns"])
                    self.assertEqual((self.base / "etc/service.conf").read_bytes(), old_config)
                    self.assertFalse(state["active"])
                    self.assertFalse(state["start_configs"])
                    deletes = [call for call in self.calls("nmcli") if "delete" in call]
                    self.assertEqual(deletes, [["nmcli", "--wait", "15", "connection", "delete", "uuid", new_uuid]])
                    self.assertFalse(self.calls("mv"))

    def test_dns_successful_modify_new_profile_is_cleaned_if_config_commit_fails(self):
        for options in (("--dns", "10.0.0.53"), ("--dns-auto",)):
            with self.subTest(options=options):
                self.write_state({"config_write_fail": True})
                self.run_script("install", "--interface", "campus0", *options, success=False)
                state = self.state()
                new_uuid = state["dns_modify_snapshots"][0]["uuid"]
                self.assertEqual(len(self.dns_calls()), 1)
                self.assertFalse(state["profiles"])
                self.assertFalse(state["profile_dns"])
                self.assertFalse(state["active"])
                self.assertFalse((self.base / "etc/service.conf").exists())
                self.assertFalse(list((self.base / "etc").glob(".service.conf.*")))
                self.assertIn(["nmcli", "--wait", "15", "connection", "delete", "uuid", new_uuid], self.calls())
                self.assertNotIn(["systemctl", "start", "minirj.service"], self.calls())
                self.assertTrue(self.calls("mv"))

    def test_dns_existing_profile_change_is_not_rolled_back_if_config_commit_fails(self):
        self.run_script("install", "--interface", "campus0", "--dns", "10.0.0.53")
        old_config = (self.base / "etc/service.conf").read_bytes()
        uuid = self.config()["MINIRJ_NM_UUID"]
        self.modify(config_write_fail=True, calls=[], stop_configs=[], start_configs=[])
        self.run_script("configure", "--dns", "10.0.0.54", "--probe-url", "https://example.com/", success=False)
        self.assert_dns_profile(uuid, "10.0.0.54")
        self.assertEqual((self.base / "etc/service.conf").read_bytes(), old_config)
        self.assertFalse(self.state()["active"])
        self.assertFalse(self.state()["start_configs"])
        self.assertEqual(len(self.state()["profiles"]), 1)
        self.assertFalse(any("delete" in call for call in self.calls("nmcli")))
        self.assertFalse(list((self.base / "etc").glob(".service.conf.*")))
        calls = self.calls()
        self.assertLess(calls.index(self.dns_calls()[0]), calls.index(self.calls("mv")[0]))


if __name__ == "__main__":
    unittest.main()
