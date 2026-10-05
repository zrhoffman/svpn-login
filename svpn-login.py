#!/usr/bin/env python3
"""Log in to a F5 BIG-IP APM VPN from a command-line using F5's
proprietary junk. Yay.

Works with OSX and Linux

TODO: verify server certificate. (requires using pyopenssl instead of
socket.ssl)
"""
import shutil
import socket, re, sys, os, time, fcntl, signal
import getpass, getopt, types
import string
import ssl
import subprocess
import threading
import urllib.parse
from base64 import b16encode
import html
from html.parser import HTMLParser
from platform import machine
from subprocess import PIPE
from typing import Union

import requests
from urllib3.exceptions import NewConnectionError

try:
    import socks
except ImportError:
    socks = None

SVPN_NAME = 'svpn'

CONFIG_FILE = '~/.svpn-login.conf'

proxy_addr = None

debug_login_dir = None


def set_non_blocking(fd):
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    flags = flags | os.O_NONBLOCK
    fcntl.fcntl(fd, fcntl.F_SETFL, flags)


def sts_result(sts):
    if os.WIFSIGNALED(sts):
        return -os.WTERMSIG(sts)
    elif os.WIFEXITED(sts):
        return os.WEXITSTATUS(sts)
    else:
        raise os.error("Not signaled or exited???")


def run(args, stdin=None):
    if isinstance(stdin, str):
        stdin = stdin.encode('utf-8')
    if stdin is not None:
        pipe_r, pipe_w = os.pipe()
    else:
        pipe_r, pipe_w = None, None

    pid = os.fork()
    if pid == 0:
        if pipe_r is not None:
            # setup stdin pipe
            os.dup2(pipe_r, 0)
            os.close(pipe_r)
            os.close(pipe_w)

        try:
            os.execv(args[0], args)
        except:
            os._exit(127)
    else:
        if pipe_r is not None:
            os.close(pipe_r)
            os.write(pipe_w, stdin)
            os.close(pipe_w)
        wpid, sts = os.waitpid(pid, 0)
        code = sts_result(sts)
        if code != 0:
            raise Exception("%r: exited with result %d" % (args, code))


class Platform:
    def __init__(self):
        self.ifconfig_path = None

    @staticmethod
    def return_first_path(paths) -> Union[str, None]:
        for path in paths:
            if os.path.exists(path):
                return path
        return None

    def find_svpn(self) -> Union[str, None]:
        pass

    def setup_route(self, ifname, gateway_ip, net, bits, action):
        pass

    def setup_dns(self, iface_name, service_id, dns_servers, dns_domains, revdns_domains, override_gateway):
        pass

    def teardown_dns(self):
        pass


class DummyPlatform:
    @staticmethod
    def setup_route(ifname, gateway_ip, net, bits, action):
        print("setup_route(ifname=%r, gateway_ip=%r, net=%r, bits=%r, action=%r" % (
            ifname, gateway_ip, net, bits, action))

    @staticmethod
    def setup_host_route(ifname, gateway_ip, net, bits):
        print("teardown_route(ifname=%r, gateway_ip=%r, net=%r, bits=%r" % (ifname, gateway_ip, net, bits))

    @staticmethod
    def setup_dns(iface_name, service_id, dns_servers, dns_domains, revdns_domains, override_gateway):
        print(
            "setup_dns(iface_name=%r, service_id=%r, dns_servers=%r, dns_domains=%r, revdns_domains=%r, override_gateway=%r)" % (
                iface_name, service_id, dns_servers, dns_domains, revdns_domains, override_gateway))

    @staticmethod
    def teardown_dns():
        print("teardown_dns()")


class DarwinPlatform(Platform):
    def __init__(self):
        if os.path.exists("/sbin/route"):
            self.route_path = "/sbin/route"
        elif os.path.exists("/usr/bin/route"):
            self.route_path = "/usr/bin/route"
        else:
            raise Exception("Couldn't find route command")

        if os.path.exists('/sbin/ifconfig'):
            self.ifconfig_path = '/sbin/ifconfig'
        elif os.path.exists('/usr/bin/ifconfig'):
            self.ifconfig_path = '/usr/bin/ifconfig'
        else:
            raise Exception("Couldn't find ifconfig command")

    def find_svpn(self) -> Union[str, None]:
        path = shutil.which(SVPN_NAME)
        if path:
            return path
        paths_to_check = [
            '/Applications/F5 VPN.app/Contents/Helpers/svpn',
            '/Library/Internet Plug-Ins/F5 SSL VPN Plugin.plugin/Contents/Helpers/svpn',
            os.path.expanduser(
                '~/Library/Internet Plug-Ins/F5 SSL VPN Plugin.plugin/Contents/Helpers/svpn'),
            './svpn']
        return self.return_first_path(paths_to_check)

    def setup_route(self, ifname, gateway_ip, net, bits, action):
        args = [self.route_path, action, '-net', "%s/%s" % (net, bits)]
        if ifname:
            args += ['-interface', ifname]
        else:
            args += [gateway_ip]
        run(args)

    @staticmethod
    def load_SystemConfigurationFramework():
        try:
            # If it's already been wrapped, we're done.
            import SystemConfiguration
            return SystemConfiguration
        except ImportError:
            # Nope, so, try again, the hard way...
            import objc
            SystemConfiguration = types.ModuleType('SystemConfiguration')
            SCbndl = objc.loadBundle(SystemConfiguration.__name__, SystemConfiguration.__dict__,
                                     bundle_identifier="com.apple.SystemConfiguration")

            objc.loadBundleFunctions(SCbndl, SystemConfiguration.__dict__, [
                (u'SCDynamicStoreCreate', '@@@@@'),
                (u'SCDynamicStoreSetValue', 'B@@@')
            ])
            return SystemConfiguration

    def setup_dns(self, iface_name, service_id, dns_servers, dns_domains, revdns_domains, override_gateway):
        """Setup DNS the OSX magic way."""
        # Preferentially use the SystemConfiguration library (included with OSX
        # 10.5) if available, as scutil has a command-length limitation of 256
        # chars. With 256 chars it's generally not reasonable to add in the
        # revdns domains, so don't bother trying.

        # NOTE: There's a 3rd party SystemConfiguration package for 10.4 which
        # seems to have a different API (that I don't support currently)
        try:
            SystemConfiguration = self.load_SystemConfigurationFramework()
            SystemConfiguration.SCDynamicStoreCreate
        except:
            # fall back to scutil.
            config = "d.init\n"
            config += "d.add ServerAddresses * %s\n" % ' '.join(dns_servers)
            if override_gateway:
                config += "d.add SearchDomains * %s\n" % ' '.join(dns_domains)
            else:
                config += "d.add SupplementalMatchDomains * %s\n" % ' '.join(dns_domains)
            config += "set State:/Network/Service/%s/DNS\n" % service_id

            run(['/usr/sbin/scutil'], stdin=config)
        else:
            def setup_helper():
                sc = SystemConfiguration.SCDynamicStoreCreate(None, "svpn-login", None, None)
                d = SystemConfiguration.NSMutableDictionary.new()
                d[u'ServerAddresses'] = dns_servers
                if override_gateway:
                    d[u'SearchDomains'] = dns_domains
                else:
                    d[u'SupplementalMatchDomains'] = dns_domains + revdns_domains
                SystemConfiguration.SCDynamicStoreSetValue(sc, 'State:/Network/Service/%s/DNS' % service_id, d)

            setup_helper()


class LinuxPlatform(Platform):
    def __init__(self):
        self.ifconfig_path = '/sbin/ifconfig'

    def find_svpn(self) -> Union[str, None]:
        path = shutil.which(SVPN_NAME)
        if path:
            return path
        paths_to_check = ['/opt/f5/vpn/svpn', '/usr/local/lib/F5Networks/SSLVPN/svpn_' + machine(), './svpn', '/usr/share/f5vpn-ng/svpn']
        return self.return_first_path(paths_to_check)

    def wait_for_interface(self, iface_name):
        iface_up = False
        already_unknown = False
        while not iface_up:
            try:
                state_file = open('/sys/class/net/%s/operstate' % iface_name)
                state = str.strip(state_file.read())
                if state == 'up':
                    iface_up = True
                    continue
                elif state == 'unknown':
                    if already_unknown:
                        iface_up = True
                        continue
                    already_unknown = True
                    print('Status of interface %s is unknown. Waiting 5 seconds...' % iface_name)
                else:
                    already_unknown = True
                    print('Interface %s is not up yet. Waiting 5 seconds...' % iface_name)
            except IOError:
                print('Interface %s does not exist yet. Waiting 5 seconds...' % iface_name)
            time.sleep(5)

        print('Interface %s is up!' % iface_name)

    def setup_route(self, ifname, gateway_ip, net, bits, action):
        if bits == 32:
            host_or_net = "-host"
        else:
            host_or_net = "-net"
        run(['/sbin/route', action, host_or_net,
             "%s/%s" % (net, bits),
             'gw', gateway_ip, 'dev', ifname])


class ManualFrobbingDNSMixin:
    resolv_conf_timestamp = 0

    def setup_dns(self, iface_name, service_id, dns_servers, dns_domains, revdns_domains, override_gateway):
        if override_gateway:
            old_resolv_conf = []
        else:
            old_resolv_conf = open("/etc/resolv.conf").readlines()

        other_lines = []
        search = ''
        nses = []
        for line in old_resolv_conf:
            line = line.rstrip('\n')
            if line.startswith('search ') or line.startswith('domain '):
                # domain entry is simply an alternative spelling for search
                search = line.split(' ', 1)[1]
            elif line.startswith('nameserver '):
                nses.append(line.split(' ', 1)[1])
            else:
                other_lines.append(line)

        new_resolv_conf = ["search %s %s" % (' '.join(dns_domains), search)]
        for ns in dns_servers + nses:
            new_resolv_conf.append("nameserver %s" % ns)
        new_resolv_conf.extend(other_lines)
        new_resolv_conf.append('')

        def _create_file():
            os.rename('/etc/resolv.conf', '/etc/resolv.conf.f5_bak')
            open('/etc/resolv.conf', 'w').write('\n'.join(new_resolv_conf))

        _create_file()

        self.resolv_conf_timestamp = os.stat('/etc/resolv.conf').st_mtime

    def teardown_dns(self):
        self._teardown_dns()

    def _teardown_dns(self):
        try:
            if self.resolv_conf_timestamp == 0:
                pass
            elif os.stat('/etc/resolv.conf').st_mtime == self.resolv_conf_timestamp:
                os.rename('/etc/resolv.conf.f5_bak', '/etc/resolv.conf')
            else:
                sys.stderr.write("Not restoring resolv.conf: modified by another process.\n")
                os.unlink('/etc/resolv.conf.f5_bak')
        except:
            pass


class ResolvConfHelperDNSMixin:
    def setup_dns(self, iface_name, service_id, dns_servers, dns_domains, revdns_domains, override_gateway):
        # FIXME: should I be doing something different here based on override_gateway?

        # ResolvConf is a system for managing your resolv.conf file in a
        # structured way on unix systems. When it is installed, go through it,
        # rather than munging the file manually (and thus causing potential
        # conflicts)

        # We append tun- to the interface so the proper record order is
        # established with the resolvconf distribution.  Since we're essentially
        # using svpn for the same reason as most people would use tun, this
        # should be okay
        self.iface_name = iface_name
        cmd = "nameserver %s\nsearch %s\n" % (' '.join(dns_servers), ' '.join(dns_domains))
        run(['/sbin/resolvconf', '-a', 'tun-%s' % iface_name], stdin=cmd)

    def teardown_dns(self):
        self._teardown_dns()

    def _teardown_dns(self):
        try:
            run(["/sbin/resolvconf", '-d', 'tun-%s' % self.iface_name])
        except:
            pass


class LinuxManualPlatform(ManualFrobbingDNSMixin, LinuxPlatform):
    pass


class LinuxResolvconfPlatform(ResolvConfHelperDNSMixin, LinuxPlatform):
    pass


def get_platform():
    if sys.platform == "darwin":
        return DarwinPlatform()
    elif sys.platform == "linux":
        # Choose a dns resolver setup routine
        if os.path.exists('/sbin/resolvconf'):
            return LinuxResolvconfPlatform()
        else:
            return LinuxManualPlatform()
    else:
        # The *BSDs aren't supported at the moment...but there's no reason they
        # can't be, when someone with such a platform tells me the syntax for
        # their "route" command. Patches welcome!
        raise Exception("Don't know how to setup routes/dns for platform %r" % sys.platform)


platform = get_platform()


def readline_from_sock(s):
    output = ''
    while 1:
        data = s.recv(1)
        if not data:
            break
        elif data == '\n':
            break
        elif data != '\r':
            output += data
    return output


def proxy_connect(ip, port):
    # Connect a socket to ip and port, and return a socket object.
    # If a proxy is defined, connect via the proxy.
    if proxy_addr and proxy_addr[0] == 'http':
        s = socket.socket()
        s.connect(proxy_addr[1:])
        s.send("CONNECT %s:%d HTTP/1.0\r\n\r\n" % (ip, port))
        statusline = readline_from_sock(s).split(' ')
        if len(statusline) < 2 or statusline[1] != '200':
            raise Exception("Proxy returned bad status for CONNECT: %r" % ' '.join(statusline))
        while 1:  # Read remaining headers, if any
            line = readline_from_sock(s)
            if line == '':
                break
        # Now the ssl connection is going
    elif proxy_addr and proxy_addr[0] == 'socks5':
        # Socks method
        s = socks.socksocket()
        s.setproxy(socks.PROXY_TYPE_SOCKS5, proxy_addr[1], proxy_addr[2])
        s.connect((ip, port))
    else:
        s = socket.socket()
        s.connect((ip, port))
    return s


def parse_hostport(host, default_port=0):
    ipport = host.split(':')
    if len(ipport) == 1:
        ip = ipport[0]
        port = 443
    else:
        ip = ipport[0]
        port = int(ipport[1])
    ip = socket.gethostbyname(ip)
    return ip, port


def send_request(host, request):
    ip, port = parse_hostport(host, 443)
    s = proxy_connect(ip, port)
    context = ssl.create_default_context()
    ssl_socket = context.wrap_socket(s, server_hostname=host)
    ssl_socket.write(request.encode('utf-8'))
    data = ''.encode('utf-8')
    while 1:
        try:
            bytes = ssl_socket.read(1)
            if len(bytes) == 0:
                break
            data += bytes
        except (socket.error, ssl.SSLError):
            break
    # print data
    return data


BROWSER_HEADERS = {
    # The access policy hangs up on clients that do not look like a browser.
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
}

VOID_TAGS = ('input', 'br', 'img', 'meta', 'link', 'hr', 'col', 'area', 'base', 'wbr')


class LogonPageParser(HTMLParser):
    """Collect the forms, field labels and messages of an APM logon page."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms = []
        self.labels = {}
        self.messages = []
        self._form = None
        self._select = None
        self._option = None
        self._button = None
        self._label_for = None
        self._label_text = ''
        self._message_depth = 0
        self._message_text = ''
        self._depth = 0

    def handle_starttag(self, tag, attrs):
        attrs = {k: (v or '') for k, v in attrs}
        if tag not in VOID_TAGS:
            self._depth += 1
            if not self._message_depth and tag in ('div', 'span', 'td', 'p', 'font') and \
                    re.search(r'error|message', attrs.get('class', '') + ' ' + attrs.get('id', ''), re.I):
                self._message_depth = self._depth
                self._message_text = ''
        if tag == 'form':
            self._form = {'attrs': attrs, 'fields': []}
            self.forms.append(self._form)
        elif tag == 'input' and self._form is not None:
            self._form['fields'].append({
                'tag': 'input', 'type': attrs.get('type', 'text').lower(), 'name': attrs.get('name', ''),
                'value': attrs.get('value', ''), 'id': attrs.get('id', ''), 'checked': 'checked' in attrs})
        elif tag == 'select' and self._form is not None:
            self._select = {'tag': 'select', 'type': 'select', 'name': attrs.get('name', ''),
                            'id': attrs.get('id', ''), 'options': []}
            self._form['fields'].append(self._select)
        elif tag == 'option' and self._select is not None:
            self._option = {'value': attrs.get('value'), 'text': '', 'selected': 'selected' in attrs}
            self._select['options'].append(self._option)
        elif tag == 'button' and self._form is not None:
            self._button = {'tag': 'button', 'type': attrs.get('type', 'submit').lower(), 'name': attrs.get('name', ''),
                            'value': attrs.get('value', ''), 'id': attrs.get('id', ''), 'checked': False, 'text': ''}
            self._form['fields'].append(self._button)
        elif tag == 'label':
            self._label_for = attrs.get('for', '')
            self._label_text = ''

    def handle_endtag(self, tag):
        if tag == 'form':
            self._form = None
        elif tag == 'select':
            self._select = None
        elif tag == 'option':
            self._option = None
        elif tag == 'button':
            self._button = None
        elif tag == 'label' and self._label_for is not None:
            self.labels[self._label_for] = ' '.join(self._label_text.split())
            self._label_for = None
        if tag in VOID_TAGS:
            return
        if self._message_depth and self._depth == self._message_depth:
            text = ' '.join(self._message_text.split())
            if text:
                self.messages.append(text)
            self._message_depth = 0
        self._depth -= 1

    def handle_data(self, data):
        if self._button is not None:
            self._button['text'] += data
        if self._option is not None:
            self._option['text'] += data
        if self._label_for is not None:
            self._label_text += data
        if self._message_depth:
            self._message_text += data


def requests_proxies():
    if proxy_addr is None:
        return None
    scheme = 'http' if proxy_addr[0] == 'http' else 'socks5h'
    url = '%s://%s:%d' % (scheme, proxy_addr[1], proxy_addr[2])
    return {'http': url, 'https': url}


def ask_field(field, label):
    if field['type'] == 'select':
        options = [o for o in field['options'] if o['value'] is not None]
        if len(options) == 1:
            return options[0]['value']
        print(label or field['name'])
        for i, option in enumerate(options):
            print('%d) %s' % (i, ' '.join(option['text'].split())))
        while True:
            choice = input('> ')
            if choice.isdigit() and int(choice) < len(options):
                return options[int(choice)]['value']
    prompt = '%s: ' % (label or field['name'])
    if field['type'] == 'password':
        return getpass.getpass(prompt)
    return input(prompt)


def choose(title, fields, labels, default=None):
    """Let the user pick one of several radio buttons or submit buttons."""
    print(title)
    for i, field in enumerate(fields):
        text = labels.get(field['id']) or ' '.join(field.get('text', '').split()) or field['value'] or field['name']
        print('%d) %s%s' % (i, text, ' (default)' if field is default else ''))
    while True:
        answer = input('> ').strip()
        if answer == '' and default is not None:
            return default
        if answer.isdigit() and int(answer) < len(fields):
            return fields[int(answer)]


def page_text(html):
    return ' '.join(re.sub(r'(?s)<(script|style).*?</\1>|<[^>]+>', ' ', html).split())


def do_login(host, username=None, auth_method=None):
    """Walk through the access policy logon pages (username/password, then
    SMS/OTP or any other prompt the server shows) and return the MRHSession."""
    base = 'https://%s' % host
    s = requests.Session()
    s.headers.update(BROWSER_HEADERS)
    proxies = requests_proxies()
    if proxies:
        s.proxies.update(proxies)

    # Let CTRL-C abort the prompts even though trap_signals() swallows SIGINT.
    old_handler = signal.signal(signal.SIGINT, signal.default_int_handler)
    try:
        r = s.get(base + '/', timeout=30)
        shown_messages = set()
        step = 0
        for _ in range(30):
            path = urllib.parse.urlparse(r.url).path
            if path.startswith('/vdesk/') and 'hangup' not in path:
                return s.cookies.get('MRHSession')
            if 'hangup' in path or 'logout' in path:
                sys.stderr.write('Login failed: %s\n' % page_text(r.text)[:500])
                return None

            if debug_login_dir:
                step += 1
                dump = os.path.join(debug_login_dir, 'step%d.html' % step)
                with open(dump, 'w') as f:
                    f.write('<!-- %s -->\n%s' % (r.url, r.text))
                print('[debug] saved %s' % dump)

            # Message and decision boxes: each link calls SubmitResult(n), which
            # posts choice=n through hidden_form using JavaScript.
            options = re.findall(r'<a[^>]+SubmitResult\((\d+)\)[^>]*>([^<]+)</a>', r.text)
            if options and 'id="hidden_form"' in r.text:
                header = re.search(r'id="interaction_table_header"[^>]*>(.*?)</td>', r.text, re.S)
                if header and page_text(header.group(1)):
                    print(html.unescape(page_text(header.group(1))))
                options = [{'id': '', 'name': '', 'value': value, 'text': html.unescape(text.strip())}
                           for value, text in options]
                option = options[0]
                if len(options) > 1:
                    wanted = [o for o in options if auth_method and o['text'].lower() == auth_method.lower()]
                    option = wanted[0] if wanted else choose('Choose:', options, {})
                    print('Selected %s' % option['text'])
                r = s.post(r.url, data=[('choice', option['value'])], timeout=60)
                continue

            page = LogonPageParser()
            page.feed(r.text)
            for message in page.messages:
                if message not in shown_messages:
                    print(message)
                    shown_messages.add(message)
            forms = [f for f in page.forms if f['attrs'].get('id') == 'auth_form'] or \
                    [f for f in page.forms if f['attrs'].get('method', '').lower() == 'post']
            if not forms:
                refresh = re.search(r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+url=([^"\'>]+)', r.text, re.I)
                if refresh:
                    r = s.get(urllib.parse.urljoin(r.url, refresh.group(1).strip()), timeout=30)
                    continue
                sys.stderr.write('Login process failed, unexpected page at %s:\n%s\n' % (r.url, page_text(r.text)[:500]))
                return None

            form = forms[0]
            data = []
            radios_done = set()
            for field in form['fields']:
                name, ftype = field['name'], field['type']
                if not name or ftype in ('submit', 'button', 'reset', 'image'):
                    continue
                if ftype == 'radio':
                    if name in radios_done:
                        continue
                    radios_done.add(name)
                    group = [f for f in form['fields'] if f['type'] == 'radio' and f['name'] == name]
                    choice = next((f for f in group if f['checked']), None)
                    if len(group) > 1:
                        choice = choose(name, group, page.labels, choice)
                    if choice is not None:
                        data.append((name, choice['value'] or 'on'))
                elif ftype == 'checkbox':
                    if field['checked']:
                        data.append((name, field['value'] or 'on'))
                elif ftype == 'hidden':
                    data.append((name, field['value']))
                elif name == 'username' and ftype == 'text':
                    if username is None:
                        username = input('Username for %s: ' % host)
                    data.append((name, username))
                elif field['tag'] == 'input' and field['value'] and ftype != 'password':
                    data.append((name, field['value']))
                else:
                    label = page.labels.get(field['id'], '')
                    if name == 'password':
                        label = '%s for %s@%s' % (label or 'Password', username, host)
                    data.append((name, ask_field(field, label)))

            # A form may offer several buttons (e.g. "Send SMS" / "Use token"); the
            # server only learns which one was pressed from its name=value pair.
            buttons = [f for f in form['fields'] if f['type'] in ('submit', 'image') and f['name']]
            if len(buttons) > 1:
                button = choose('Which button to press?', buttons, page.labels)
                data.append((button['name'], button['value']))
            elif buttons:
                data.append((buttons[0]['name'], buttons[0]['value']))

            action = urllib.parse.urljoin(r.url, form['attrs'].get('action') or r.url)
            r = s.post(action, data=data, timeout=60)
        sys.stderr.write('Login process failed, too many logon steps.\n')
        return None
    finally:
        signal.signal(signal.SIGINT, old_handler)


def get_vpn_menu_number(host, session):
    # Find out the "Z" parameter to use to open a VPN connection
    request = """GET /vdesk/vpn/index.php3?outform=xml HTTP/1.0\r
Accept: */*\r
Accept-Language: en\r
Cookie: uRoamTestCookie=TEST; VHOST=standard; MRHSession=%(session)s\r
Referer: https://%(host)s/my.activation.php3\r
User-Agent: Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en) AppleWebKit/417.9 (KHTML, like Gecko) Safari/417.9.2\r
Host: %(host)s\r
\r
""" % dict(host=host, session=session)
    result = send_request(host, request).decode('utf-8')

    if re.search('HTTP/[0-9.]+ 302( Found)?', result):
        # a redirect to the login page.
        sys.stderr.write("Old session no longer valid.\n")
        return None

    # strip off the http header, we want just the xml...
    favxmlstr = result[result.find('<?xml '):]

    if len(favxmlstr) == 0:
        raise NameError("Invalid response getting VPN connection list")

    from xml.dom import minidom
    xmldoc = minidom.parseString(favxmlstr)

    # parse the xml return and build datastructure of the options
    favs = []
    for favxml in xmldoc.getElementsByTagName('favorite'):
        name = favxml.getElementsByTagName('name')[0].firstChild.wholeText
        favid = favxml.attributes['id'].value
        z_matches = re.search(r'Z=(\S+,\S+)&', favid)
        if z_matches is not None:
            favid = z_matches.group(1)

        favs.append({'name': name, 'id': favid})

    # import pprint
    # pp = pprint.PrettyPrinter()
    # pp.pprint(favs)

    # let the user select which vpn connection they'd like to use...
    if len(favs) == 1:
        selected_fav = 0
    else:
        selected_fav = -1
        while selected_fav < 0 or selected_fav > len(favs) - 1:
            print("Select VPN connection:")

            for i, v in enumerate(favs):
                print(str(i) + ") " + v['name'])

            selected_fav = int(input())

    print("Connecting to " + favs[selected_fav]['name'])

    return favs[selected_fav]['id'] or None


def get_VPN_params(host, session, menu_number):
    request = """GET /vdesk/vpn/connect.php3?resourcename=%(menu_number)s&outform=xml&client_version=1.1 HTTP/1.0\r
Accept: */*\r
Accept-Language: en\r
Cookie: uRoamTestCookie=TEST; VHOST=standard; MRHSession=%(session)s\r
Referer: https://%(host)s/vdesk/index.php3\r
User-Agent: Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en) AppleWebKit/417.9 (KHTML, like Gecko) Safari/417.9.2\r
Host: %(host)s\r
\r
""" % dict(menu_number=menu_number, session=session, host=host)
    result = send_request(host, request).decode('utf-8')
    # print "RESULT:", result

    # Try to find the plugin parameters
    matches = list(re.finditer("<embed [^>]*?(version=[^>]*)>", result))
    if not matches:
        # A new version of the server has switched to using javascript to write
        # the parameters, now, so try matching that too.
        matches = list(re.finditer(r"document.writeln\('(version=[^)]*)'\)", result))

    if not matches:
        xml_match = re.search(pattern=r'<\?xml.*<favorite.*<object\s+ID="ur_Host".+?</favorite>', string=result,
                              flags=re.DOTALL)
        if xml_match is not None:
            paramsDict = decode_xml_params(xml_match.group(0))
            return paramsDict

    if not matches:
        if re.search('^Location: /my.logon.php3', result):
            # a redirect to the login page.
            sys.stderr.write("Old session no longer valid.\n")
            return None
        sys.stderr.write("Embed info output:\n")
        sys.stderr.write(result)
        return None

    match = matches[-1]
    params = match.group(1)
    params = params.replace(' ', '&').replace('"', '')
    paramsDict = decode_params(params)
    # print paramsDict
    return paramsDict


def decode_xml_params(xml_param_str):
    paramsDict = {}
    from xml.dom.minidom import parseString, Element
    xmldoc = parseString(xml_param_str)
    for element in xmldoc.getElementsByTagName('object')[0].childNodes:
        if not isinstance(element, Element):
            continue
        if element.firstChild is None:
            value = ''
        else:
            value = element.firstChild.wholeText.strip(string.whitespace)
        paramsDict[element.tagName] = value

    return paramsDict


def decode_params(paramsStr):
    paramsDict = {}
    for param in paramsStr.split('&'):
        if param == '':
            continue
        k, v = param.split('=', 1)
        if re.match('q[0-9]+', k):
            k, v = v.decode('hex').split('=', 1)
        paramsDict[k] = v

    return paramsDict


def encode_hex_query_string(params: dict) -> str:
    param_index = 0
    query_string = ''
    for key, value in params.items():
        hex_string = b16encode((key + '=' + value).encode('utf-8')).decode('utf-8')
        query_string += 'q%(index)d=%(hex)s' % dict(index=param_index, hex=hex_string) + '&'
        param_index += 1
    return query_string


class LogWatcher:
    """Collect (iface_name, tty, local_ip, remote_ip) from the svpn log messages
    and call svpn_ip_up when they've all arrived."""

    collected_log = ''
    iface_name = tty = remote_ip = local_ip = None
    notified = False

    def __init__(self, ip_up):
        self.ip_up = ip_up

    def _get_match(self, exp):
        match = re.search(exp, self.collected_log, re.MULTILINE)
        if match is not None:
            return match.group(1)

    def process(self, logmsg):
        print("SVPN LOG: %r" % logmsg)

        self.collected_log += logmsg

        if self.iface_name is None:
            self.iface_name = self._get_match("Using interface (.*)$")
        if self.tty is None:
            self.tty = self._get_match("Connect: .* <--> (.*)$")
        if self.remote_ip is None:
            self.remote_ip = self._get_match("remote IP address (.*)$")
        if self.local_ip is None:
            self.local_ip = self._get_match("local  IP address (.*)$")

        if not (self.notified or
                self.iface_name is None or self.tty is None or
                self.remote_ip is None or self.local_ip is None):
            print("CALLING ip_up%r" % ((self.iface_name, self.tty, self.local_ip, self.remote_ip),))
            self.notified = True
            self.ip_up(self.iface_name, self.tty, self.local_ip, self.remote_ip)


def keepalive(host: str, port: str):
    keepalive_url = 'http://%(host)s:%(port)s' % dict(host=host, port=port)
    try:
        while True:
            time.sleep(1)
            if requests.get(keepalive_url, timeout=50).status_code != 200 and reconnect:
                break
    except Exception:
        print('Ending keepalive to %s' % keepalive_url)


def execSVPN(svpn_path: str, query_string: str):
    returncode = subprocess.run([svpn_path], check=True, input=query_string.encode('utf-8'),
                                stdout=PIPE, stderr=PIPE).returncode
    print('SVPN has exited with a status of %i.' % returncode)


def usage(exename, s):
    print(
        "Usage: %s [--skip-dns] [--skip-routes] [--sessionid=sessionid] [--auth-method=SMS|Token] [--debug-login] [--{http,socks5}-proxy=host:port] [[user@]host]" % exename)


def need_svpn(exename):
    print(
        """
The F5 svpn executable is required in order to use %(exename)s. Follow the instructions in the %(exename)s README
in order to get svpn, then try running %(exename)s again.
        """ % dict(exename=exename))


def get_prefs():
    try:
        conf = open(os.path.expanduser(CONFIG_FILE))
    except:
        return None

    return conf.readline()


def write_prefs(line):
    try:
        f = open(os.path.expanduser(CONFIG_FILE), 'w')
        f.write(line)
    except:
        print("Couldn't write prefs file: %s" % CONFIG_FILE)


reconnect = True


def signal_trap(signal, frame):
    global reconnect
    reconnect = False


def trap_signals():
    global reconnect
    signals = [
        signal.SIGHUP,
        signal.SIGINT,
        signal.SIGQUIT,
        signal.SIGABRT,
        signal.SIGTERM,
    ]
    for sig in signals:
        signal.signal(sig, signal_trap)


def main(argv):
    global proxy_addr, debug_login_dir
    svpn_path = platform.find_svpn()
    if svpn_path is None:
        need_svpn(argv[0])
        sys.exit(1)

    skip_dns = False
    skip_routes = False

    if '--help' in argv:
        usage(argv[0], sys.stdout)
        sys.exit(0)

    if sys.version_info < (2, 3, 5):
        sys.stderr.write("Python 2.3.5 or later is required.\n")
        sys.exit(1)

    # Set effective uid to userid; will become root as necessary
    os.seteuid(os.getuid())
    user = getpass.getuser()

    opts, args = getopt.getopt(argv[1:], "",
                               ['http-proxy=', 'sessionid=', 'reconnect=', 'socks5-proxy=', 'skip-routes', 'skip-dns',
                                'debug-login', 'auth-method='])

    if len(args) > 1:
        usage(argv[0], sys.stderr)
        sys.exit(1)

    prefs = get_prefs()
    old_session = None
    session = None
    userhost = None
    global reconnect
    reconnect = True
    if prefs is not None:
        path, userhost, old_session = prefs.split('\0')

    if len(args) > 0:
        if args[0] != userhost:
            # Don't attempt to reuse session if switching users or servers.
            old_session = None
        userhost = args[0]

    if userhost is None:
        sys.stderr.write("The host argument must be provided the first time.\n")
        sys.exit(1)

    login_user = None
    auth_method = None
    if '@' in userhost:
        user, host = userhost.split('@')
        login_user = user
    else:
        host = userhost

    for opt, val in opts:
        if opt in ('--http-proxy'):
            proxy_addr = ('http',) + parse_hostport(val)
            sys.stderr.write("Using proxy: %r\n" % (proxy_addr,))
        elif opt in ('--socks5-proxy'):
            if socks is None:
                sys.stderr.write("Cannot use a socks5 proxy: you do not seem to have the socks module available.\n")
                sys.stderr.write("Please install SocksiPy: http://socksipy.sourceforge.net/\n")
                sys.exit(1)
            proxy_addr = ('socks5',) + parse_hostport(val)
            sys.stderr.write("Using proxy: %r\n" % (proxy_addr,))
        elif opt in ('--skip-dns'):
            skip_dns = True
        elif opt in ('--skip-routes'):
            skip_routes = True
        elif opt in ('--sessionid'):
            session = val
        elif opt == '--auth-method':
            auth_method = val
        elif opt == '--debug-login':
            import tempfile
            debug_login_dir = tempfile.mkdtemp(prefix='svpn-login-')
        elif opt in ('--reconnect'):
            reconnect = str(val).lower()[0] not in ('f', 'n', 0)
        else:
            sys.stderr.write("Unknown option: %s\n" % opt)
            sys.exit(1)

    params = None

    if session is None and old_session is not None:
        print("Trying old session...")
        menu_number = get_vpn_menu_number(host, old_session)
        if menu_number is not None:
            params = get_VPN_params(host, old_session, menu_number)
            session = old_session

    has_connected = False
    trap_signals()
    while True:
        if params is None:
            if session is None:
                session = do_login(host, login_user, auth_method)
                if session is None:
                    sys.exit(3)
                print("Session id gotten:", session)

            print("Getting params...")
            menu_number = get_vpn_menu_number(host, session)
            if menu_number is None:
                if not (has_connected):
                    sys.stderr.write(
                        "Unable to find the 'Network Access' entry in main menu. Do you have VPN access?\n")
                else:
                    sys.stderr.write('VPN session has expired.')
                sys.exit(1)

            params = get_VPN_params(host, session, menu_number)

        if params is None:
            print("Couldn't get embed info. Sorry.")
            sys.exit(2)

        params['browser_pid'] = str(os.getpid())
        params['version'] = '2.9'
        if skip_dns:
            for dns_key in ['DNS0', 'DNS6_0', 'DNSSuffix0', 'DNSRegisterConnection0', 'DNSUseDNSSuffixForRegistration0',
                            'DNS_SPLIT0', 'EnforceDNSOrder0']:
                del params[dns_key]
        if skip_routes:
            params['ExcludeSubnets0'] = params['LAN0']
            params['ExcludeSubnets6_0'] = params['LAN6_0']

        query_string = encode_hex_query_string(params)
        write_prefs('\0'.join(['', userhost, session]))
        print("Got plugin params, execing vpn client")

        try:
            threading.Thread(target=keepalive, args=[params['host0'], params['port0']]).start()
            execSVPN(svpn_path, query_string)
        except KeyboardInterrupt:
            pass
        except SystemExit as se:
            print(se)
        print("Shut-down.")
        has_connected = True
        if not (reconnect):
            break
        params = None
        print('Restarting...')


if __name__ == '__main__':
    main(sys.argv)
