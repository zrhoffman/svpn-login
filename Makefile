# Run make PYTHON=/usr/bin/python2.4 or w.e. if /usr/bin/python isn't suitable.
PYTHON ?= /usr/bin/python

build:
	gcc -DPYTHON=\"$(PYTHON)\" -o f5vpn-login-runner f5vpn-login-runner.c

install: build
	rm -f /usr/local/sbin/f5vpn-login
	cp f5vpn-login.py /usr/local/sbin/f5vpn-login.py
	cp f5vpn-login-runner /usr/local/bin/f5vpn-login
	chmod u+s /usr/local/bin/f5vpn-login

clean:
	rm f5vpn-login-runner