
# F5 SSLVPN Command-line client

This project allows you to connect to an [F5 Networks](https://f5.com/) VPN server (BIG-IP APM) using the proprietary FastPPP protocol but without any graphical frontend.

## Setup

### Acquire svpn

The script requires [`svpn`](https://support.f5.com/csp/article/K14947#SVPN), which is a component of the BIG-IP Edge Client. If you already have the BIG-IP Edge Client installed, then you already have `svpn`.

Otherwise, if you are on macOS, you can get it by going to https://[your-VPN-server]/ in a web browser, clicking on "Edge Client - macOS", unzipping the file you downloaded, and running the installer that you unzipped.

If you are on Linux, choose one of the following options depending on which distro you run.

| Distro | Option |
--- | ---
| Ubuntu or Debian | https://[your-VPN-server]/public/download/linux_f5vpn.x86_64.deb |
|  CentOS/Red Hat | https://[your-VPN-server]/public/download/linux_f5vpn.x86_64.rpm |
|  Arch Linux | Install the [f5fpc](https://aur.archlinux.org/packages/f5fpc)<sup>AUR</sup> package |

### Acquire svpn-login

```
$ git clone https://github.com/zrhoffman/svpn-login.git
$ cd svpn-login
```

## Basic Usage (supports two-factor authentication):

```bash
./svpn-login.py --sessionid=0123456789abcdef0123456789abcdef [hostname]
```

You can find the session ID by going to the VPN host in a web browser, logging in, and running this JavaScript in Developer Tools:

```javascript
document.cookie.match(/MRHSession=(.*?); /)[1]
```

If your organization does not use 2FA and you are able to log in with just your username and password:

```bash
./svpn-login.py [user@host]
```

## DNS and Routing

- By default, the script will change your DNS servers to the ones provided by the VPN server. Skip this step by by passing the `--skip-dns` option.

- By default, once connected, the script will route all traffic through the newly-created VPN network interface. Skip this step by passing the `--skip-routes` option (your VPN connection will be useless if this option is used, so only use it if you plan to set up the routing table yourself).

## Other Info

*[user@host] is saved for future invocations, so doesn't need to be specified on future invocations.*

Use **CTRL-C** to exit.

The application will save `[user@host]` and last session ID in ``~/.svpn-login.conf``. If no user was given, [host] will still be saved. In case of problems or for reset the session data simply remove that file.
