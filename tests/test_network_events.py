import unittest
from unittest.mock import Mock
from minirj.core.state_machine import StateMachine, AuthState
from minirj.network.events import NetworkEvent
from minirj.network.snapshot import IPv4Snapshot
from test_state_machine import (CLIENT, SERVER, CHALLENGE_1, FakeClock, TimedNetwork,
                                request, result, hello_policy)

A = IPv4Snapshot('192.0.2.2', '255.255.255.0', '192.0.2.1', '192.0.2.53')
B = IPv4Snapshot('192.0.2.3', '255.255.255.0', '192.0.2.1', '192.0.2.53')


class Events:
    def __init__(self, schedule):
        self.schedule = list(schedule)

    def poll(self, now):
        events = []
        while self.schedule and self.schedule[0][0] <= now:
            events.append(self.schedule.pop(0)[1])
        return events


class EventTests(unittest.TestCase):
    def make(self, schedule=(), frames=(), stop_at=5):
        clock = FakeClock()
        net = TimedNetwork(frames, clock, stop_at)
        machine = StateMachine('fake0', 'user', 'synthetic', net_engine=net,
                               snapshot_provider=Mock(read=Mock(return_value=A)),
                               event_source=Events(schedule), monotonic=clock,
                               dhcp_mode=0, request_timeout=1,
                               retransmit_interval=.5, hello_rand=lambda: 0)
        net.machine = machine
        machine._read_network_snapshot()
        return machine, net, clock

    def online(self, machine):
        machine.state = AuthState.WAIT_ID_REQ
        for frame in (request(1, 1), request(4, 2, b'\x10' + CHALLENGE_1),
                      result(3, 2, hello_policy(1, 1))):
            machine._handle_packet(frame, CLIENT, lambda _: None)
        self.assertTrue(machine._session_authenticated)

    def test_link_down_clears_every_session_component(self):
        m, net, clock = self.make()
        self.online(m)
        m.dhcp_auth_phase = m.tlv_encoder.dhcp_auth_phase = 2
        m._address_deadline = m._next_address_poll = 3
        self.assertTrue(m.inject_network_event(NetworkEvent('fake0', False)))
        for name in ('server_mac','_phase_server_mac','_last_request_key','_last_response',
                     '_last_md5_identifier','_last_md5_challenge','_hello_codec',
                     '_hello_interval','_next_hello','last_private_properties',
                     '_address_deadline','_next_address_poll'):
            self.assertIsNone(getattr(m, name), name)
        self.assertFalse(m._session_authenticated)
        self.assertEqual(m.dhcp_auth_phase, 0)
        self.assertEqual(m.tlv_encoder.fake_ip, '0.0.0.0')
        before = len(net.sent)
        m._send_due_hello(100)
        m._handle_packet(request(1, 3), CLIENT, lambda _: None)
        self.assertEqual(len(net.sent), before)
        self.assertIsNone(m._poll_network_events(100))
        self.assertEqual(m.logoff(lambda _: None), 'Logoff not sent: no authenticated session')

    def test_duplicates_and_unrelated_interface_do_not_restart(self):
        m, net, clock = self.make()
        self.online(m)
        for event in (NetworkEvent('other', False), NetworkEvent('fake0', True, A),
                      NetworkEvent('fake0', True, IPv4Snapshot(**{**A.__dict__, 'warnings':('new',)}))):
            self.assertFalse(m.inject_network_event(event))
        self.assertEqual(m.state, AuthState.ONLINE)

    def test_address_change_debounces_and_refreshes_tlv(self):
        m, net, clock = self.make()
        self.online(m)
        self.assertTrue(m.inject_network_event(NetworkEvent('fake0', True, B)))
        due = m._recovery_due
        self.assertFalse(m.inject_network_event(NetworkEvent('fake0', True, B), .4))
        self.assertEqual(m._recovery_due, due)
        self.assertIsNone(m._poll_network_events(.49))
        self.assertEqual(m._poll_network_events(.5), 'restart')
        self.assertEqual(m.tlv_encoder.fake_ip, B.ip)
        self.assertEqual(m.state, AuthState.WAIT_ID_REQ)
        self.assertIsNone(m.server_mac)
        self.assertIsNone(m._poll_network_events(.6))

    def test_flap_backoff_caps_and_stable_online_resets(self):
        m, _, clock = self.make()
        for i in range(20):
            m.inject_network_event(NetworkEvent('fake0', False), i * 20)
            m.inject_network_event(NetworkEvent('fake0', True), i * 20 + 1)
        self.assertEqual(m._recovery_delay, 8)
        self.assertEqual(m._recovery_due, 389)
        self.assertEqual(m._poll_network_events(389), 'restart')
        clock.value = 390
        self.online(m)
        m._poll_network_events(398)
        self.assertEqual(m._recovery_delay, .5)

    def test_phase1_address_delivery_does_not_destroy_exchange(self):
        m, _, _ = self.make()
        m.state = AuthState.WAIT_ADDRESS
        m.server_mac = SERVER
        m.dhcp_auth_phase = 1
        self.assertFalse(m.inject_network_event(NetworkEvent('fake0', True, B)))
        self.assertEqual(m.state, AuthState.WAIT_ADDRESS)
        self.assertEqual(m._read_network_snapshot(), B)
        self.assertTrue(m.inject_network_event(NetworkEvent('fake0', False)))
        self.assertEqual(m.dhcp_auth_phase, 0)

    def test_runner_does_not_resurrect_old_online_after_link_loss(self):
        frames = [request(1,1), request(4,2,b'\x10'+CHALLENGE_1), result(3,2,hello_policy(1,1))]
        m, net, clock = self.make([(0.2, NetworkEvent('fake0', False))], frames, stop_at=3)
        self.assertFalse(m.authenticate(lambda _: None))
        self.assertFalse(m._session_authenticated)
        self.assertEqual(len(net.sent), 4)  # Start, Identity, MD5, immediate Hello only

    def test_initial_down_never_sends_and_recovery_is_wired(self):
        m, net, _ = self.make([(0, NetworkEvent('fake0', False))], stop_at=2)
        self.assertFalse(m.authenticate(lambda _: None))
        self.assertEqual(net.sent, [])
        m, net, _ = self.make([(0, NetworkEvent('fake0', False)),
                              (1, NetworkEvent('fake0', True, B))], stop_at=2.2)
        self.assertFalse(m.authenticate(lambda _: None))
        self.assertEqual(len(net.sent), 1)
        self.assertEqual(m.tlv_encoder.fake_ip, B.ip)

    def test_invalid_config_and_script_recovery_rejected(self):
        for kwargs in ({'recovery_debounce':0}, {'recovery_max_backoff':float('nan')},
                       {'event_source':Events([]), 'network_backend':'script', 'dhcp_script':'/fake'}):
            with self.assertRaises(ValueError):
                StateMachine('fake0','u','p', **kwargs)


class ProductionEventTests(unittest.TestCase):
    make = EventTests.make
    online = EventTests.online
    def source(self, **kwargs):
        from minirj.network.events import LinuxNetworkEventSource
        return LinuxNetworkEventSource('fake0', **kwargs)

    def test_poll_cadence_and_same_ip_dns_do_not_reauthenticate(self):
        from dataclasses import replace
        reader = Mock(return_value=(2, True))
        provider = Mock(read=Mock(return_value=A))
        source = self.source(read_link=reader, snapshot_provider=provider)
        m, net, _ = self.make()
        self.online(m)
        m.event_source = source
        self.assertIsNone(m._poll_network_events(0))
        self.assertEqual(source.poll(.49), ())
        provider.read.return_value = replace(A, dns='203.0.113.53', secondary_dns='203.0.113.54')
        before = len(net.sent)
        self.assertIsNone(m._poll_network_events(.5))
        self.assertEqual(m.state, AuthState.ONLINE)
        self.assertEqual(len(net.sent), before)
        self.assertEqual(m._event_snapshot.dns, '203.0.113.53')
        self.assertEqual(provider.read.call_count, 2)

    def test_unknown_missing_down_and_return_are_distinct(self):
        reader = Mock(side_effect=[PermissionError('sensitive'), (None, False), (2, False), (2, True), (2, True)])
        source = self.source(read_link=reader, snapshot_provider=Mock(read=Mock(return_value=A)))
        for now, status in enumerate(('unknown', 'missing', 'down', 'up')):
            event, = source.poll(now)
            self.assertEqual(source.status, status)
            self.assertEqual(event.link_up, status == 'up')
            self.assertNotIn('sensitive', repr(event))

    def test_snapshot_failure_clears_session_and_blocks_stale_hello(self):
        source = self.source(read_link=Mock(return_value=(2, True)),
                             snapshot_provider=Mock(read=Mock(side_effect=RuntimeError('sensitive'))))
        m, net, _ = self.make()
        self.online(m)
        m.event_source = source
        before = len(net.sent)
        self.assertEqual(m._poll_network_events(0), 'invalidated')
        m._send_due_hello(99)
        m._poll_network_events(99)
        self.assertEqual(len(net.sent), before)
        self.assertEqual(m.network_observation_status, 'unknown')
        self.assertIsNone(m._event_snapshot)

    def test_empty_address_is_known_and_route_read_failure_unknown(self):
        from dataclasses import replace
        provider = Mock(read=Mock(return_value=IPv4Snapshot()))
        source = self.source(read_link=Mock(return_value=(2, True)), snapshot_provider=provider)
        self.assertTrue(source.poll(0)[0].link_up)
        provider.read.return_value = replace(A, warnings=("route diagnostics",),
                                             observation_errors=("route_unavailable",))
        self.assertEqual(source.poll(1)[0].status, 'unknown')
        provider.read.return_value = replace(A, warnings=('/etc/resolv.conf: unavailable',))
        self.assertTrue(source.poll(2)[0].link_up)

    def test_snapshot_straddling_link_replacement_is_unknown(self):
        source = self.source(read_link=Mock(side_effect=[(2, True), (3, True)]),
                             snapshot_provider=Mock(read=Mock(return_value=A)))
        self.assertEqual(source.poll(0)[0].status, 'unknown')

    def test_interface_replacement_rebinds_once_after_debounce(self):
        m, net, _ = self.make()
        m.inject_network_event(NetworkEvent('fake0', True, A, ifindex=2), 0)
        self.online(m)
        net.close = Mock()
        net.open = Mock()
        self.assertTrue(m.inject_network_event(NetworkEvent('fake0', False, status='missing'), 1))
        self.assertTrue(m.inject_network_event(NetworkEvent('fake0', True, A, ifindex=3), 2))
        due = m._recovery_due
        self.assertIsNone(m._poll_network_events(due-.01))
        self.assertEqual(m._poll_network_events(due), 'restart')
        net.close.assert_called_once()
        net.open.assert_called_once()
        m._poll_network_events(due+1)
        net.open.assert_called_once()

    def test_gateway_and_mask_remain_change_evidence(self):
        from dataclasses import replace
        for snapshot in (replace(A, netmask='255.255.0.0'), replace(A, gateway='192.0.2.254')):
            m, _, _ = self.make()
            self.online(m)
            self.assertTrue(m.inject_network_event(NetworkEvent('fake0', True, snapshot)))

    def test_ioctl_absent_address_vs_unreadable(self):
        import errno
        from unittest.mock import patch
        from minirj.network.events import _strict_ioctl
        for code, expected in ((errno.EADDRNOTAVAIL, OSError), (errno.EPERM, RuntimeError)):
            with patch('minirj.network.events.fcntl.ioctl', side_effect=OSError(code, 'secret')):
                with self.assertRaises(expected):
                    _strict_ioctl(1, 2, b'')

    def test_logging_redacts_credentials(self):
        m, _, _ = self.make()
        log = Mock()
        m._log(log, 'failed user synthetic')
        self.assertEqual(log.call_args.args[0], 'failed [redacted] [redacted]')

    def test_kernel_readonly_link_query(self):
        from minirj.network.events import read_linux_link, LinuxNetworkEventSource
        import socket
        index, up = read_linux_link('lo')
        self.assertEqual(index, socket.if_nametoindex('lo'))
        self.assertIsInstance(up, bool)
        event, = LinuxNetworkEventSource('no-such-test0').poll(0)
        self.assertEqual(event.status, 'missing')

    def test_initial_missing_can_stop_without_open_or_send(self):
        m, net, _ = self.make()
        def missing(_):
            m.stop()
            return None, False
        m.event_source = self.source(read_link=missing)
        net.open = Mock()
        self.assertFalse(m.authenticate(lambda _: None))
        net.open.assert_not_called()
        self.assertEqual(net.sent, [])


    def test_malformed_ioctl_is_unknown_not_empty_address(self):
        from unittest.mock import patch
        from minirj.network.events import _strict_ioctl
        with patch('minirj.network.events.fcntl.ioctl', return_value=b'bad'):
            with self.assertRaises(RuntimeError):
                _strict_ioctl(1, 2, b'')

    def test_getlink_requires_carrier_admin_up_and_usable_operstate(self):
        import socket
        import struct
        from unittest.mock import patch
        from minirj.network.events import read_linux_link
        for flags, carrier, state, expected in ((1,1,6,True), (1,1,0,True),
                                               (0,1,6,False), (1,0,6,False),
                                               (1,1,2,False), (1,1,5,False)):
            body = struct.pack('=BBHiII', 0, 0, 0, 2, flags, 0)
            for kind, value in ((33,carrier), (16,state)):
                body += struct.pack('=HHB3x', 5, kind, value)
            data = struct.pack('=IHHII', 16+len(body), 16, 0, 1, 0) + body
            sock = Mock()
            sock.recvmsg.return_value = (data, [], 0, (0,0))
            factory = Mock()
            factory.return_value.__enter__ = Mock(return_value=sock)
            factory.return_value.__exit__ = Mock(return_value=False)
            with patch('minirj.network.events.socket.socket', factory), \
                 patch('minirj.network.events.socket.if_nametoindex', return_value=2):
                self.assertEqual(read_linux_link('fake0'), (2,expected))
            factory.assert_called_once_with(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE)
            sent, dest = sock.sendto.call_args.args
            self.assertEqual(struct.unpack_from('=H', sent, 4)[0], 18)  # GET, never SETLINK
            self.assertEqual(dest, (0,0))

    def test_production_source_runs_address_recovery_through_runner(self):
        frames = [request(1,1), request(4,2,b'\x10'+CHALLENGE_1), result(3,2,hello_policy(1,1))]
        m, net, clock = self.make(frames=frames, stop_at=2)
        m.event_source = self.source(read_link=Mock(return_value=(2,True)),
                                     snapshot_provider=Mock(read=lambda _: A if clock() < .5 else B))
        self.assertFalse(m.authenticate(lambda _: None))
        self.assertEqual(m.tlv_encoder.fake_ip, B.ip)
        self.assertIsNone(m._hello_codec)
        self.assertGreaterEqual(len(net.sent), 5)


class ProductionIORecoveryTests(unittest.TestCase):
    # Runner + production polling, with only clock/kernel/raw-I/O seams faked.
    def make_io(self, site="recv", code=None, *, monitor=True, observed_up=False):
        import errno
        from unittest.mock import patch
        from minirj.network.events import LinuxNetworkEventSource
        code = errno.ENETDOWN if code is None else code
        clock = FakeClock()

        class Network(TimedNetwork):
            def __init__(self):
                super().__init__([], clock, 12)
                self.failed_at = None
                self.outage_until = None
                self.errors = []
                self.wire = []
                self.counts = {}
                self.queries = []
                self.waits = []
                self.recovered = False
                self.operations = 0

            def fail(self):
                if self.failed_at is None:
                    self.failed_at = clock()
                    self.failed_wire_index = len(self.wire)
                    self.outage_until = clock() + .7
                self.errors.append(clock())
                raise OSError(code, "synthetic interface failure")

            def bounded(self):
                self.operations += 1
                if self.operations > 500:
                    raise AssertionError("runner spun without bounded progress")

            def send_frame(self, frame):
                self.bounded()
                kind = ("start" if frame[15] == 1 else "hello" if frame[15] == 0xbf
                        else "identity" if frame[22] == 1 else "md5")
                self.counts[kind] = self.counts.get(kind, 0) + 1
                target, occurrence = {
                    "start_retry": ("start", 2), "hello_timer": ("hello", 2),
                    "recovery_start": ("start", 2), "phase2_start": ("start", 2),
                    "initial_start": ("start", 1)
                }.get(site, (site, 1))
                if self.failed_at is None and kind == target and self.counts[kind] == occurrence:
                    self.fail()
                if self.outage_until is not None and clock() < self.outage_until:
                    self.fail()
                self.wire.append((clock(), frame))
                if kind == "start" and (site != "start_retry" or self.failed_at is not None):
                    self.frames = [request(1, 1), request(4, 2, b"\x10" + CHALLENGE_1),
                                   result(3, 2, hello_policy(1, 1))]
                if kind == "hello" and self.failed_at is not None:
                    self.recovered = True
                return super().send_frame(frame)

            def recv_frame(self, timeout=0):
                self.bounded()
                if self.recovered:
                    self.machine.stop()
                    return None
                if site == "recv" and self.failed_at is None and clock() >= .6:
                    self.fail()
                if self.outage_until is not None and clock() < self.outage_until:
                    self.fail()
                return super().recv_frame(timeout)

            def read_link(self, _):
                self.queries.append(clock())
                if not observed_up and self.outage_until is not None and clock() < self.outage_until:
                    return (None, False) if code in (errno.ENODEV, errno.ENXIO) else (2, False)
                return 2, True

            def wait(self, timeout):
                self.waits.append(timeout)
                clock.value += timeout
                if clock() >= self.stop_at:
                    self.machine.stop()
                return self.machine._stop_event.is_set()

        net = Network()
        source = LinuxNetworkEventSource("fake0", read_link=net.read_link,
                                        snapshot_provider=Mock(read=lambda _: B if site == "recovery_start" and clock() >= .8 else A))
        machine = StateMachine("fake0", "user", "synthetic", net_engine=net,
                               snapshot_provider=Mock(read=Mock(return_value=A)),
                               event_source=source if monitor else None,
                               monotonic=clock, dhcp_mode=int(site == "phase2_start"), request_timeout=2,
                               retransmit_interval=.5, hello_rand=lambda: 0)
        net.machine = machine
        if site == "initial_start":
            machine._read_network_snapshot()  # No bootstrap invalidation; exercise outer initial send.
        waiter = patch.object(machine._stop_event, "wait", side_effect=net.wait)
        waiter.start()
        self.addCleanup(waiter.stop)
        return machine, net, clock

    def assert_recovered(self, machine, net):
        self.assertTrue(machine.authenticate(lambda _: None))
        self.assertTrue(net.recovered)
        self.assertIsNotNone(net.failed_at)
        self.assertTrue(net.waits, "immediate persistent I/O errors must be paced")
        self.assertTrue(all(wait > 0 for wait in net.waits))
        after = net.wire[net.failed_wire_index:]
        self.assertTrue(after)
        self.assertGreaterEqual(after[0][0], net.outage_until)
        self.assertEqual(after[0][1][15], 1, "restart, never an old Hello/response replay")
        self.assertFalse(net.opened)
        self.assertLess(net.operations, 150)

    def test_recv_link_loss_between_polls_recovers_without_busy_loop(self):
        machine, net, _ = self.make_io()
        self.assert_recovered(machine, net)


    def test_missing_device_io_recovers_with_monitor(self):
        import errno
        for code in (errno.ENODEV, errno.ENXIO):
            with self.subTest(code=code):
                machine, net, _ = self.make_io(code=code)
                self.assert_recovered(machine, net)

    def test_all_active_send_paths_unwind_and_restart_on_link_loss(self):
        for site in ("initial_start", "start", "start_retry", "recovery_start", "phase2_start",
                     "identity", "md5", "hello", "hello_timer"):
            with self.subTest(site=site):
                machine, net, _ = self.make_io(site)
                self.assert_recovered(machine, net)

    def test_send_missing_device_recovers_even_if_poll_never_saw_missing(self):
        import errno
        for code in (errno.ENODEV, errno.ENXIO):
            with self.subTest(code=code):
                machine, net, _ = self.make_io("start", code, observed_up=True)
                self.assert_recovered(machine, net)

    def test_unclassified_and_unmonitored_errors_still_propagate(self):
        import errno
        for site in ("recv", "start", "hello"):
            for monitor, code in ((True, errno.EIO), (True, errno.EPERM),
                                  (False, errno.ENETDOWN), (False, errno.ENODEV),
                                  (False, errno.ENXIO)):
                with self.subTest(site=site, monitor=monitor, code=code):
                    machine, net, _ = self.make_io(site, code, monitor=monitor)
                    with self.assertRaises(OSError) as error:
                        machine.authenticate(lambda _: None)
                    self.assertEqual(error.exception.errno, code)
                    self.assertFalse(net.opened)
                    self.assertFalse(net.waits)

    def test_unclassified_error_during_recovery_is_not_swallowed(self):
        import errno
        machine, net, _ = self.make_io("start")
        receive = net.recv_frame
        def broken_receive(timeout=0):
            if net.failed_at is not None:
                raise OSError(errno.EIO, "unrelated error during recovery")
            return receive(timeout)
        net.recv_frame = broken_receive
        with self.assertRaises(OSError) as error:
            machine.authenticate(lambda _: None)
        self.assertEqual(error.exception.errno, errno.EIO)


class ReplacementRunnerTests(unittest.TestCase):
    def make_replacement(self, *, exchange=False):
        from minirj.network.events import LinuxNetworkEventSource
        clock = FakeClock()
        new_mac = bytes.fromhex("001122334466")

        class Network(TimedNetwork):
            def __init__(self):
                super().__init__([], clock, 6)
                self.wire = []
                self.opens = 0
                self.new_hello = False

            def open(self):
                super().open()
                self.opens += 1
                self.mac_addr = CLIENT if clock() < .7 else new_mac

            def send_frame(self, frame):
                self.wire.append((clock(), frame, self.mac_addr))
                if exchange and frame[15] == 1:
                    identity = request(1, 1)
                    md5 = request(4, 2, b"\x10" + CHALLENGE_1)
                    success = result(3, 2, hello_policy(1, 1))
                    frames = [identity, identity, md5, md5, success]
                    if self.mac_addr == new_mac:
                        # Same id/challenge from the old session must not revive
                        # ONLINE or its response/Hello cache before fresh Identity.
                        frames = [success, md5] + frames
                    self.frames = [self.mac_addr + f[6:] for f in frames]
                if frame[15] == 0xbf and self.mac_addr == new_mac:
                    self.new_hello = True
                return super().send_frame(frame)

            def recv_frame(self, timeout=0):
                if self.new_hello:
                    self.machine.stop()
                    return None
                return super().recv_frame(timeout)

        net = Network()
        source = LinuxNetworkEventSource("fake0", read_link=lambda _: (2 if clock() < .7 else 3, True),
                                        snapshot_provider=Mock(read=Mock(return_value=A)))
        machine = StateMachine("fake0", "user", "synthetic", net_engine=net,
                               snapshot_provider=Mock(read=Mock(return_value=A)),
                               event_source=source, monotonic=clock, dhcp_mode=0,
                               request_timeout=1, retransmit_interval=.5, hello_rand=lambda: 0)
        net.machine = machine
        return machine, net, new_mac

    def test_outer_retry_after_rebind_never_uses_initial_mac(self):
        machine, net, new_mac = self.make_replacement()
        self.assertFalse(machine.authenticate(lambda _: None))
        self.assertEqual(net.opens, 2)
        after = [(when, frame, mac) for when, frame, mac in net.wire if mac == new_mac]
        self.assertGreaterEqual(len(after), 5, "cover outer retries, not only first recovery Start")
        self.assertEqual([(when, frame[6:12].hex(), mac.hex()) for when, frame, mac in after
                          if frame[6:12] != mac], [])
        self.assertEqual(machine.tlv_encoder.mac_address, new_mac)

    def test_new_mac_responses_duplicates_and_hello_ignore_old_session(self):
        machine, net, new_mac = self.make_replacement(exchange=True)
        self.assertTrue(machine.authenticate(lambda _: None))
        self.assertEqual(net.opens, 2)
        frames = [frame for _, frame, mac in net.wire if mac == new_mac]
        self.assertEqual([frame[6:12] for frame in frames], [new_mac] * 6)
        self.assertEqual([frame[15] for frame in frames], [1, 0, 0, 0, 0, 0xbf])
        self.assertEqual(frames[1], frames[2])
        self.assertEqual(frames[3], frames[4])
        old_md5 = next(frame for _, frame, mac in net.wire
                       if mac == CLIENT and frame[15] == 0 and frame[22] == 4)
        self.assertNotEqual(frames[3], old_md5)
