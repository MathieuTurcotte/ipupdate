# Dynamic IP address updater for DynDNS

`ipupdate.py` is a daemon that monitor your external IP address and update
your DynDNS records when it changes.

## Usage

```
Usage: ipupdate.py [options] CONFIG_FILE

Options:
  -h, --help    show this help message and exit
  -d, --daemon  run as daemon
  -l LOG_LEVEL  log level (debug, info, warning, error, critical)

```

## Installing

A fabric script is provided to install `ipupdate.py` as a daemon. It should
work on modern Ubuntu and Fedora distributions.

```
fab install:path/to/your/config -H localhost
```

## Tests

To run the unit tests, Python 3.3 or higher is required.

```
python3 -m unittest -v ipupdate_test.py
```

## License

This code is free to use under the terms of the [MIT license](http://mturcotte.mit-license.org/).
