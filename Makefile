# Run 'make PYTHON=/usr/bin/python2.4' or w.e. if /usr/bin/python isn't suitable.
# You may also specify the install prefix by appending e.g. "PREFIX=/usr/local"
PYTHON ?= /usr/bin/python
PREFIX ?= /usr

build:
	gcc -DPYTHON=\"$(PYTHON)\" -DPREFIX=\"$(PREFIX)\" -o f5vpn-login-runner f5vpn-login-runner.c

install: build
	cp f5vpn-login.py $(PREFIX)/sbin/f5vpn-login.py
	cp f5vpn-login-runner $(PREFIX)/bin/f5vpn-login
	chmod u+s $(PREFIX)/bin/f5vpn-login

clean:
	rm f5vpn-login-runner
