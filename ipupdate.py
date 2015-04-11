#!/usr/bin/env python3

# Copyright (c) 2012 Mathieu Turcotte
# Licensed under the MIT license.

import configparser
import logging
import logging.handlers
import optparse
import os
import pwd
import random
import re
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


def ping(host):
    fd = os.open(os.devnull, os.O_RDWR)
    try:
        ping_cmd = ["ping", "-q", "-c1", host]
        ping_ret = subprocess.call(ping_cmd, stdout=fd, stderr=fd, stdin=fd)
        return ping_ret == 0
    finally:
        os.close(fd)


class ConnectionMonitor:
    PING_HOSTS = ["www.google.com", "www.yahoo.com",
                  "www.facebook.com", "www.bing.com",
                  "www.youtube.com", "www.stackoverflow.com"]

    def __init__(self, ping=ping):
        self.ping = ping

    def connected(self):
        random.shuffle(self.PING_HOSTS)
        for host in self.PING_HOSTS:
            if self.ping(host):
                return True
        return False


class ExternalIpLookupService:
    """Wrapper around an external IP lookup service. Can be configured to
    enforce a minimal delay between each queries."""

    # Over-simplified regular expression to match IP address.
    ip_regex = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")

    def __init__(self, name, url, min_delay_between_query=0):
        self.name = name
        self.url = url
        self.min_delay_between_query = min_delay_between_query
        self.last_query_time = 0
        self.logger = logging.getLogger("ipupdate.ExternalIpLookupService")

    def ready(self):
        # Check if the elapsed time since the last query is
        # greater than the maximal query rate for this service.
        delay_since_last_query = int(time.time()) - self.last_query_time
        return self.min_delay_between_query < delay_since_last_query

    def query(self):
        if not self.ready():
            return None

        self.logger.info("Querying %s." % self.name)
        self.last_query_time = int(time.time())

        try:
            response = urllib.request.urlopen(self.url, None, 30)
            content = response.read().decode("utf-8")
            ip = self.ip_regex.search(content)
            if ip is not None:
                ip = ip.group(0)
                self.logger.info("%s" % ip)
                return ip
        except urllib.error.HTTPError as err:
            error = "HTTPError (%s) querying %s." % (err.code, self.name)
            self.logger.error(error)
            return None
        except urllib.error.URLError as err:
            error = "URLError (%s) querying %s." % (err.reason, self.name)
            self.logger.error(error)
            return None

        self.logger.warning("No IP address in %s response." % self.name)
        return None


class ExternalIpLookupServicePool:
    """The ExternalIpLookupServicePool holds many ExternalIpLookupService
    instances. This allow the IpWatchDogDaemon to do more queries while,
    hopefully, increasing the overall success rate."""

    def __init__(self, services):
        self.services = services
        self.logger = logging.getLogger("ipupdate.ExternalIpLookupServicePool")

    def add(self, service):
        self.services.append(service)

    # Returns true if at least one external IP lookup service is ready to handle
    # a request.
    def ready(self):
        for service in self.services:
            if service.ready():
                return True
        return False

    def query(self):
        for service in self.services:
            ip = service.query()
            if ip is not None:
                return ip

        self.logger.warning("Can't determine the external IP address.")
        return None


class DynResponseParser:
    """Handles the parsing of the responses returned by the Dyn DNS API."""

    _dyn_error_regex = re.compile(r"^(!?[a-z0-9]+)$")
    _host_error_regex = re.compile(r"^([a-z]+) (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$")

    def parse(self, response, hostnames):
        err = self._parse_dyn_error(response)
        statuses = self._parse_parts(response, hostnames) if not err else {}
        return err, statuses

    def _parse_dyn_error(self, response):
        err = self._dyn_error_regex.match(response)
        return err.group(0) if err else None

    def _parse_parts(self, response, hostnames):
        response_parts = response.split('\n')
        statuses = {}

        if len(response_parts) != len(hostnames):
            raise Exception("Reponse/hostnames length mismatch!")

        for hostname, part in zip(hostnames, response_parts):
            statuses[hostname] = self._parse_part(part)

        return statuses

    def _parse_part(self, part):
        matches = self._host_error_regex.match(part)
        if not matches:
            raise Exception("Could not parse host status.")
        return matches.group(1), matches.group(2)


class DynService:
    """Simple wrapper around urllib to perform GET request against the Dyn DNS
    REST API."""

    base_url = "https://members.dyndns.org/"
    update_url = "https://members.dyndns.org/nic/update"

    # The HTTP status code returned by Dyn DNS may be a 500 in case the return
    # code is 911 or dnserr. This class overrides urllib's default behavior
    # which is to raise an exception when this status code is returned. That
    # way, it's actually possible to read the Dyn DNS return code.
    class IgnoreError500(urllib.request.BaseHandler):
        def http_error_500(self, request, response, code, msg, hdrs):
            return response

    def __init__(self, username, password, response_parser):
        self.logger = logging.getLogger("ipupdate.DynService")
        self.response_parser = response_parser
        pswd_manager = urllib.request.HTTPPasswordMgrWithDefaultRealm()
        pswd_manager.add_password(user=username, passwd=password,
                                  realm=None, uri=self.base_url)
        auth_handler = urllib.request.HTTPBasicAuthHandler(pswd_manager)
        self.opener = urllib.request.build_opener(auth_handler,
                                                  self.IgnoreError500)

    def send_update(self, ip, hostnames):
        params = urllib.parse.urlencode({
            "hostname": ",".join(hostnames),
            "myip": ip
        })
        request_url = "%s?%s" % (self.update_url, params)
        self.logger.debug("Send request: '%s'" % request_url)
        response = self.opener.open(request_url)
        response_content = response.read().decode("utf-8").strip()
        self.logger.debug("Got response: '%s'" % response_content)
        return self.response_parser.parse(response_content, hostnames)


# API datails can be found at http://dyn.com/support/developers/api/
class DynUpdater:
    """Handles the entire external IP updating process from update submission
    to response parsing."""

    system_errors = {
        "badauth": "Bad authorization (username or password).",
        "!donator": "The offline setting was set and the user is not a donator.",
        "badagent": "The user agent was not sent or HTTP method is not permitted.",
        "911": "There is a problem or scheduled maintenance on Dyn DNS.",
        "dnserr": "DNS error encountered."
    }

    ok_codes = ["good", "nochg"]

    def __init__(self, hostnames, dns_service):
        self.logger = logging.getLogger("ipupdate.DynUpdater")
        self.hostnames = hostnames
        self.dns_service = dns_service

    def update(self, ip):
        try:
            return self._do_update(ip)
        except urllib.error.HTTPError as err:
            err_msg = "HTTPError (%s)." % err.code
            self.logger.error(err_msg)
        except urllib.error.URLError as err:
            err_msg = "URLError (%s)." % err.reason
            self.logger.error(err_msg)
        return False

    def _do_update(self, ip):
        err, statuses = self.dns_service.send_update(ip, self.hostnames)

        if err:
            msg = self.system_errors.get(err, "Unknown error code.")
            self.logger.error("%s: %s" % (err, msg))
            return False
        else:
            for hostname, status in statuses.items():
                self.logger.info("%s %s %s" % (hostname, status[0], status[1]))

            return all(map(lambda status:
                           status[0] in self.ok_codes,
                           statuses.values()))


class IpWatchDog:
    """The IpWatchDog periodically checks the external ip address by querying
    an ExternalIpLookupService. When a change of the external IP address is
    detected, an update request is issued using a DNS updater."""

    def __init__(self, connection_monitor, ip_lookup_service,
                 dns_updater, check_interval):
        self.logger = logging.getLogger("ipupdate.IpWatchDog")
        self.connection_monitor = connection_monitor
        self.ip_lookup_service = ip_lookup_service
        self.dns_updater = dns_updater
        self.check_interval = check_interval
        self.current_ip = None

    def watch(self):
        while True:
            self.update()
            time.sleep(self.check_interval)

    def update(self):
        try:
            self._do_update()
        except Exception:
            self.logger.exception("Unhandled exception during update.")

    def _do_update(self):
        if not self.connection_monitor.connected():
            self.logger.warning("No connection, skipping update.")
            return

        ip = self.ip_lookup_service.query()

        if ip is not None and ip != self.current_ip:

            self.logger.info("Updating external IP address to %s." % ip)
            if self.dns_updater.update(ip):
                self.logger.info("Updated external IP address to %s." % ip)
                self.current_ip = ip
            else:
                self.logger.info("Failed to update external IP address.")


def daemonize():
    try:
        if os.fork() != 0:
            os._exit(0)

        os.setsid()

        if os.fork() != 0:
            os._exit(0)

        os.chdir("/")

        # Always turn off group and other write bit when creating new files.
        os.umask(0o022)

        # Change current user. Notice that the call order is important since
        # after the setuid() call, the effective UID isn't 0 any more while
        # calling setgid() requires root privileges.
        pwd_entry = pwd.getpwnam("ipupdate")
        os.setgid(pwd_entry.pw_gid)
        os.setuid(pwd_entry.pw_uid)
    except OSError as err:
        print("OSError(%s, %s)." % (err.strerror, err.errno), file=sys.stderr)
        exit(1)


def configure_logging(options):
    msgfmt = "%(asctime)s (%(levelname)s) %(name)s: %(message)s"
    datefmt = "%Y-%m-%d %H:%M:%S"
    formatter = logging.Formatter(fmt=msgfmt, datefmt=datefmt)

    RotatingFileHandler = logging.handlers.RotatingFileHandler
    rotating_file_handler = RotatingFileHandler(options.log_file,
                                                maxBytes=options.log_size,
                                                backupCount=options.log_num)
    rotating_file_handler.setFormatter(formatter)

    levels = {
        "debug": logging.DEBUG,
        "info": logging.INFO,
        "warning": logging.WARNING,
        "error": logging.ERROR,
        "critical": logging.CRITICAL
    }

    logger = logging.getLogger("ipupdate")
    logger.setLevel(levels[options.log_level])
    logger.addHandler(rotating_file_handler)

    if options.daemonize:
        fd = os.open(os.devnull, os.O_RDWR)
        os.dup2(fd, sys.stdin.fileno())
        os.dup2(fd, sys.stdout.fileno())
        os.dup2(fd, sys.stderr.fileno())
        os.close(fd)


# The init process will send a SIGTERM signal at shutdown.
def sigterm_handler(signum, frame):
    logging.getLogger("ipupdate").info("SIGTERM received, shutting down.")
    logging.shutdown()
    exit(0)


def configure_signals():
    signal.signal(signal.SIGTERM, sigterm_handler)


def parse_args():
    usage = "usage: %prog [options] CONFIG_FILE"
    argparser = optparse.OptionParser(usage=usage)
    argparser.add_option("-d", "--daemon",
                         action="store_true",
                         default=False,
                         dest="daemonize",
                         help="run as daemon")
    argparser.add_option("-l",
                         action="store",
                         choices=["debug", "info", "warning",
                                  "error", "critical"],
                         default="info",
                         dest="log_level",
                         help="log level (debug, info, warning, error, critical)")

    # options contains all the optional arguments
    # args contains all the positional arguments
    (options, args) = argparser.parse_args()

    if len(args) != 1:
        argparser.error("no configuration file")

    options.config_filename = args[0]

    if not os.path.isfile(options.config_filename):
        argparser.error("configuration file doesn't exist")

    return options


def parse_config(options):
    config = configparser.SafeConfigParser({
        "check_interval": 60 * 5,
        "log_file": "ipupdate.log",
        "log_size": 1024 * 128,
        "log_num": 5
    })

    try:
        config.read(options.config_filename)
        options.log_file = config.get("logging", "log_file")
        options.log_size = config.getint("logging", "log_size")
        options.log_num = config.getint("logging", "log_num")
        options.username = config.get("account", "username")
        options.password = config.get("account", "password")
        options.check_interval = config.getint("configuration", "check_interval")
        options.hosts = config.get("configuration", "hosts").split(",")
    except configparser.Error as err:
        # Logging isn't enabled yet.
        print(err, file=sys.stderr)
        exit(1)

    return options


def main():
    options = parse_args()
    parse_config(options)

    if options.daemonize:
        configure_signals()
        daemonize()

    # Make sure to configure logging after the process has been daemonized,
    # otherwise, the log files will be opened with the wrong permissions.
    configure_logging(options)

    response_parser = DynResponseParser()
    dns_service = DynService(options.username, options.password, response_parser)
    dns_updater = DynUpdater(options.hosts, dns_service)

    ip_lookup_service_pool = ExternalIpLookupServicePool([
        ExternalIpLookupService("ipappspot", "http://ip.appspot.com/", 60),
        ExternalIpLookupService("easydns", "http://support.easydns.com/utils/get_ip.php", 360),
        ExternalIpLookupService("dyndns", "http://checkip.dyndns.org/", 720),
        ExternalIpLookupService("ifconfig", "http://ifconfig.me/ip", 300),
        ExternalIpLookupService("icanhazip", "http://icanhazip.com/", 300),
        ExternalIpLookupService("externalip", "http://api.externalip.net/ip/", 300),
        ExternalIpLookupService("dnsomatic", "http://myip.dnsomatic.com/", 300)
    ])

    logging.getLogger("ipupdate").info("Started.")

    watchdog = IpWatchDog(ConnectionMonitor(), ip_lookup_service_pool,
                          dns_updater, options.check_interval)
    watchdog.watch()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
