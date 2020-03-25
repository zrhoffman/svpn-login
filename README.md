# F5 VPN Command-line client

This software allows you to connect to an [F5 Networks](https://f5.com/) VPN server without using their
browser plugin. It also has the advantage of setting up DNS properly on OSX
systems, which the official client doesn't do. (but maybe they will in the
future, now that they can copy the method I use).

**It is not supported or affiliated with F5 in any way.** I actually find it rather
sad the client they provide is so terribly poor that I had to write this in
order to get reliable access to my company's VPN.

This software does not require any software from F5 to be installed on the
client. The only requirement is Python 2.3.5 or later. It works on at least
Linux and OSX systems, but porting to any similar OS should be trivial. Porting
to Windows, on the other hand, is probably not reasonably possible.

## Install

Build:
```bash
make install
```
as root.

Add to path:
`cat export PATH=$PATH:/usr/local/bin >> .bash_profile` # for bash
`cat export PATH=$PATH:/usr/local/bin >> .zsh_profile` # for zsh

## Usage

As normal user:

```bash
f5vpn-login user@host
```

*user@host is saved for future invocations, so doesn't need to be
specified on future invocations.*

Use **CTRL-C** to exit.

The application will save "user@host" and last session in ``~/.f5vpn-login.conf``. In case of problems or for reset the session data simply remove that file.


## Authors

 * James Y Knight, <foom@fuhm.net>
 * Daniele Napolitano, <dnax88@gmail.com>

