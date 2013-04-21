#!/usr/bin/python3

# Copyright (c) 2012 Mathieu Turcotte
# Licensed under the MIT license.

# python3 -m unittest -v ipupdate_test.py

import io
import logging
import mock
import time
import unittest
import urllib.request

import ipupdate

# Shut up logging during unit tests execution.
logging.disable(logging.CRITICAL)


class ConnectionMonitorTest(unittest.TestCase):
    def setUp(self):
        self.ping = mock.Mock()
        self.monitor = ipupdate.ConnectionMonitor(ping=self.ping)

    def test_single_ping_failure_are_ignored(self):
        self.ping.side_effect = [False, False, True]
        self.assertTrue(self.monitor.connected())

    def test_not_connected_when_all_ping_failed(self):
        self.ping.return_value = False
        self.assertFalse(self.monitor.connected())

    def test_ping_different_hostnames(self):
        self.ping.return_value = False

        self.monitor.connected()

        hostnames = [call[0][0] for call in self.ping.call_args_list]
        self.assertEqual(len(hostnames), len(set(hostnames)))


class ExternalIpLookupServiceTest(unittest.TestCase):
    SERVICE_NAME = "test"
    SERVICE_URL = "http://example.com/"
    CHECK_DELAY = 180
    START_TIME = 1000.0  # Must be greater than the check delay.
    IP_ADDRESS = "192.168.2.10"

    def setUp(self):
        mock.patch('time.time').start()
        time.time.return_value = self.START_TIME

        mock.patch('urllib.request.urlopen').start()
        self.response = mock.Mock(spec_set=io.RawIOBase)
        self.response.read.return_value = self.IP_ADDRESS.encode()
        urllib.request.urlopen.return_value = self.response

        self.ip_lookup_service = ipupdate.ExternalIpLookupService(
                self.SERVICE_NAME, self.SERVICE_URL, self.CHECK_DELAY)

    def tearDown(self):
        mock.patch.stopall()

    def test_first_ready_check_is_true(self):
        self.assertTrue(self.ip_lookup_service.ready())

    def test_ready_check_after_less_than_delay_is_false(self):
        self.ip_lookup_service.query()
        time.time.return_value = self.START_TIME + self.CHECK_DELAY - 1
        self.assertFalse(self.ip_lookup_service.ready())

    def test_ready_check_after_delay_is_true(self):
        self.ip_lookup_service.query()
        time.time.return_value = self.START_TIME + self.CHECK_DELAY + 1
        self.assertTrue(self.ip_lookup_service.ready())

    def test_find_ip_address(self):
        self.assertEqual(self.IP_ADDRESS, self.ip_lookup_service.query())

    def test_find_ip_address_in_haystack(self):
        ip = "192.168.255.4"
        haystack = b"<p>Your ip is:<em>" + ip.encode("utf-8") + b"</em></p>"
        self.response.read.return_value = haystack
        self.assertEqual(ip, self.ip_lookup_service.query())

    def test_return_none_if_no_ip_in_response(self):
        self.response.read.return_value = b"bad request"
        self.assertIsNone(self.ip_lookup_service.query())


class ExternalIpLookupServicePoolTest(unittest.TestCase):
    def setUp(self):
        self.service1 = mock.Mock(spec_set=ipupdate.ExternalIpLookupService)
        self.service2 = mock.Mock(spec_set=ipupdate.ExternalIpLookupService)
        self.service3 = mock.Mock(spec_set=ipupdate.ExternalIpLookupService)
        self.pool = ipupdate.ExternalIpLookupServicePool([
            self.service1, self.service2, self.service3
        ])

    def test_ready_is_true_if_one_service_is_ready(self):
        self.service1.ready.return_value = False
        self.service2.ready.return_value = False
        self.service3.ready.return_value = True
        self.assertTrue(self.pool.ready())

    def test_ready_is_false_if_no_service_is_ready(self):
        self.service1.ready.return_value = False
        self.service2.ready.return_value = False
        self.service3.ready.return_value = False
        self.assertFalse(self.pool.ready())

    def test_should_query_services_until_ip_is_determined(self):
        self.service1.query.return_value = None
        self.service2.query.return_value = None
        self.service3.query.return_value = "192.168.2.10"
        self.assertEqual(self.pool.query(), "192.168.2.10")


class DynResponseParserTest(unittest.TestCase):
    def setUp(self):
        self.parser = ipupdate.DynResponseParser()
        self.hostnames = ["duplika.ca", "mathieuturcotte.ca", "test.com"]

    def test_response_with_dyn_error(self):
        response = self.parser.parse("dnserr", [])
        self.assertEqual(response, ("dnserr", {}))

    def test_response_with_host_statuses(self):
        response = self.parser.parse("\n".join([
            "good 192.168.2.10",
            "nochg 192.168.2.10",
            "abuse 192.168.2.10"]), self.hostnames)
        self.assertEqual(response, (None, {
            self.hostnames[0]: ("good", "192.168.2.10"),
            self.hostnames[1]: ("nochg", "192.168.2.10"),
            self.hostnames[2]: ("abuse", "192.168.2.10")}))

    def test_response_with_host_number_mismatch(self):
        with self.assertRaises(Exception):
            self.parser.parse("\n".join([
                "good 192.168.2.10",
                "abuse 192.168.2.10"]), self.hostnames)

    def test_response_with_malformed_host_status(self):
        with self.assertRaises(Exception):
            self.parser.parse("\n".join([
                "good 192.168.2.10 10"
            ]), ["test.ca"])


class DynUpdaterTest(unittest.TestCase):
    def setUp(self):
        self.ip = "192.168.2.10"
        self.hostnames = ["duplika.ca", "mathieuturcotte.ca"]
        self.dyn_service = mock.Mock(spec_set=ipupdate.DynService)
        self.dyn_updater = ipupdate.DynUpdater(self.hostnames, self.dyn_service)

    def test_send_update_called(self):
        self.dyn_service.send_update.return_value = (None, {})
        self.dyn_updater.update(self.ip)
        self.dyn_service.send_update.assert_called_with(self.ip, self.hostnames)

    def test_handle_dyn_error(self):
        self.dyn_service.send_update.return_value = ("dnserr", {})
        self.assertFalse(self.dyn_updater.update(self.ip))

    def test_handle_succesful_hosts(self):
        self.dyn_service.send_update.return_value = (None, {
            self.hostnames[0]: ('nochg', self.ip),
            self.hostnames[1]: ('good', self.ip)})
        self.assertTrue(self.dyn_updater.update(self.ip))

    def test_handle_host_errors(self):
        self.dyn_service.send_update.return_value = (None, {
            self.hostnames[0]: ('good', self.ip),
            self.hostnames[1]: ('notfqn', self.ip)})
        self.assertFalse(self.dyn_updater.update(self.ip))

    def test_handle_url_error(self):
        url_error = urllib.error.URLError(None)
        self.dyn_service.send_update.side_effect = url_error
        self.assertFalse(self.dyn_updater.update(self.ip))

    def test_handle_http_error(self):
        http_error = urllib.error.HTTPError(None, None, None, None, None)
        self.dyn_service.send_update.side_effect = http_error
        self.assertFalse(self.dyn_updater.update(self.ip))


class IpWatchDogTest(unittest.TestCase):
    def setUp(self):
        self.connection_monitor = mock.Mock(spec_set=ipupdate.ConnectionMonitor)
        self.ip_lookup_service = mock.Mock(spec_set=ipupdate.ExternalIpLookupService)
        self.dns_updater = mock.Mock(spec_set=ipupdate.DynUpdater)
        self.connection_monitor.connected.return_value = True

        self.watchdog = ipupdate.IpWatchDog(self.connection_monitor,
                self.ip_lookup_service, self.dns_updater, 180)

    def test_ip_service_not_queried_when_no_connection(self):
        self.connection_monitor.connected.return_value = False
        self.watchdog.update()
        self.assertEqual(self.ip_lookup_service.query.call_count, 0)
        self.assertEqual(self.dns_updater.update.call_count, 0)

    def test_external_ip_is_not_updated_without_change(self):
        self.ip_lookup_service.query.return_value = "192.168.2.10"
        # The first call should update the external IP address while the second
        # one doesn't since the IP address hasn't changed between calls.
        self.watchdog.update()
        self.watchdog.update()
        self.assertEqual(self.ip_lookup_service.query.call_count, 2)
        self.dns_updater.update.assert_called_once_with("192.168.2.10")

    def test_external_ip_gets_updated_on_change(self):
        ip_addresses = ["192.168.2.10", "192.168.2.11", "192.168.2.12"]
        for ip_address in ip_addresses:
            self.ip_lookup_service.query.return_value = ip_address
            self.watchdog.update()
        self.dns_updater.update.assert_has_calls(
            [mock.call(ip) for ip in ip_addresses], any_order=False)

if __name__ == "__main__":
    unittest.main()
