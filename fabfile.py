# Copyright (c) 2012 Mathieu Turcotte
# Licensed under the MIT license.

from fabric.api import *
from fabric.utils import *
from fabric.colors import *
from fabric.contrib.files import exists

LOG_DIR="/var/log/ipupdate"
ETC_DIR="/usr/local/etc"
BIN_DIR="/usr/local/bin"

def add_user(username):
    sudo('adduser --system --no-create-home %s' % username)

def install_python3(is_fedora):
    if is_fedora:
        sudo('yum --assumeyes install python3')
    else:
        sudo('apt-get --assume-yes install python3')

def configure_logging():
    sudo("mkdir -p %s" % LOG_DIR)
    sudo("chown -R ipupdate:ipupdate %s" % LOG_DIR)

def install_conf_file(config_file):
    put(config_file, "%s/ipupdate.conf" % ETC_DIR, use_sudo=True, mode=0644)
    sudo("chown ipupdate:ipupdate %s/ipupdate.conf" % ETC_DIR)

def install_init_script(is_fedora):
    if is_fedora:
        put("systemd/ipupdate.service", "/lib/systemd/system/ipupdate.service", use_sudo=True, mode=0644)
    else:
        put("upstart/ipupdate.conf", "/etc/init/ipupdate.conf", use_sudo=True, mode=0644)

def install_script():
    put("ipupdate.py", "%s/ipupdate.py" % BIN_DIR, use_sudo=True, mode=0755)

@task()
def install(config_file):
    is_fedora = exists('/etc/fedora-release')
    install_python3(is_fedora)
    add_user("ipupdate")
    install_conf_file(config_file)
    install_init_script(is_fedora)
    configure_logging()
    install_script()
