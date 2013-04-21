# Copyright (c) 2012 Mathieu Turcotte
# Licensed under the MIT license.

from fabric.api import *
from fabric.utils import *
from fabric.colors import *
from fabric.contrib.files import exists

USER="ipupdate"
LOG_DIR="/var/log/ipupdate"
ETC_DIR="/usr/local/etc"
BIN_DIR="/usr/local/bin"

def chown(path):
    sudo("chown -R %s:%s %s" % (USER, USER, path))

def add_user():
    with settings(hide("warnings"), warn_only=True):
        sudo('adduser --system --no-create-home %s' % USER)

def configure_logging():
    sudo("mkdir -p %s" % LOG_DIR)
    chown(LOG_DIR)

def install_config(config_file):
    put(config_file, "%s/ipupdate.conf" % ETC_DIR, use_sudo=True, mode=0644)
    chown("%s/ipupdate.conf" % ETC_DIR)

def install_service():
    if exists('/etc/fedora-release'):
        put("systemd/ipupdate.service", "/lib/systemd/system/ipupdate.service", use_sudo=True, mode=0644)
    else:
        put("upstart/ipupdate.conf", "/etc/init/ipupdate.conf", use_sudo=True, mode=0644)

def install_script():
    put("ipupdate.py", "%s/ipupdate.py" % BIN_DIR, use_sudo=True, mode=0755)

@task()
def install(config_file):
    add_user()
    install_script()
    install_config(config_file)
    configure_logging()
    install_service()
