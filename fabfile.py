# Copyright (c) 2012 Mathieu Turcotte
# Licensed under the MIT license.

from fabric.api import *
from fabric.utils import *
from fabric.colors import *
from fabric.contrib.files import exists

def add_user(username):
    sudo('adduser --system --no-create-home %s' % username)

def install_python3(is_fedora):
    if is_fedora:
        sudo('yum --assumeyes install python3')
    else:
        sudo('apt-get --assume-yes install python3')

def configure_logging():
    sudo("mkdir -p /var/log/ipupdate")
    sudo("chown -R ipupdate:ipupdate /var/log/ipupdate")

def install_conf_file(config_file):
    put(config_file, "/usr/local/etc/ipupdate.conf", use_sudo=True, mode=0644)
    sudo("chown ipupdate:ipupdate /usr/local/etc/ipupdate.conf")

def install_init_script(is_fedora):
    if is_fedora:
        put("systemd/ipupdate.service", "/lib/systemd/system/ipupdate.service", use_sudo=True, mode=0644)
    else:
        put("upstart/ipupdate.conf", "/etc/init/ipupdate.conf", use_sudo=True, mode=0644)

def install_script():
    put("ipupdate.py", "/usr/local/bin/ipupdate.py", use_sudo=True, mode=0755)

@task()
def install(config_file):
    is_fedora = exists('/etc/fedora-release')
    install_python3(is_fedora)
    add_user("ipupdate")
    install_conf_file(config_file)
    install_init_script(is_fedora)
    configure_logging()
    install_script()
