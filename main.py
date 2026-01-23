meh = """

from urllib.parse import urlparse
import _socket
from _socket import *
import os, sys, io, selectors
from enum import IntEnum, IntFlag
try:
    import errno
except ImportError:
    errno = None
EBADF = getattr(errno, 'EBADF', 9)
EAGAIN = getattr(errno, 'EAGAIN', 11)
EWOULDBLOCK = getattr(errno, 'EWOULDBLOCK', 11)

__all__ = ["fromfd", "getfqdn", "create_connection", "create_server",
           "has_dualstack_ipv6", "AddressFamily", "SocketKind"]
__all__.extend(os._get_exports_list(_socket))
IntEnum._convert_(
        'AddressFamily',
        __name__,
        lambda C: C.isupper() and C.startswith('AF_'))
IntEnum._convert_(
        'SocketKind',
        __name__,
        lambda C: C.isupper() and C.startswith('SOCK_'))
IntFlag._convert_(
        'MsgFlag',
        __name__,
        lambda C: C.isupper() and C.startswith('MSG_'))
IntFlag._convert_(
        'AddressInfo',
        __name__,
        lambda C: C.isupper() and C.startswith('AI_'))

_LOCALHOST    = '127.0.0.1'
_LOCALHOST_V6 = '::1'


def _intenum_converter(value, enum_klass):
    try:
        return enum_klass(value)
    except ValueError:
        return value
if sys.platform.lower().startswith("win"):
    errorTab = {}
    errorTab[6] = "Specified event object handle is invalid."
    errorTab[8] = "Insufficient memory available."
    errorTab[87] = "One or more parameters are invalid."
    errorTab[995] = "Overlapped operation aborted."
    errorTab[996] = "Overlapped I/O event object not in signaled state."
    errorTab[997] = "Overlapped operation will complete later."
    errorTab[10004] = "The operation was interrupted."
    errorTab[10009] = "A bad file handle was passed."
    errorTab[10013] = "Permission denied."
    errorTab[10014] = "A fault occurred on the network??"  # WSAEFAULT
    errorTab[10022] = "An invalid operation was attempted."
    errorTab[10024] = "Too many open files."
    errorTab[10035] = "The socket operation would block."
    errorTab[10036] = "A blocking operation is already in progress."
    errorTab[10037] = "Operation already in progress."
    errorTab[10038] = "Socket operation on nonsocket."
    errorTab[10039] = "Destination address required."
    errorTab[10040] = "Message too long."
    errorTab[10041] = "Protocol wrong type for socket."
    errorTab[10042] = "Bad protocol option."
    errorTab[10043] = "Protocol not supported."
    errorTab[10044] = "Socket type not supported."
    errorTab[10045] = "Operation not supported."
    errorTab[10046] = "Protocol family not supported."
    errorTab[10047] = "Address family not supported by protocol family."
    errorTab[10048] = "The network address is in use."
    errorTab[10049] = "Cannot assign requested address."
    errorTab[10050] = "Network is down."
    errorTab[10051] = "Network is unreachable."
    errorTab[10052] = "Network dropped connection on reset."
    errorTab[10053] = "Software caused connection abort."
    errorTab[10054] = "The connection has been reset."
    errorTab[10055] = "No buffer space available."
    errorTab[10056] = "Socket is already connected."
    errorTab[10057] = "Socket is not connected."
    errorTab[10058] = "The network has been shut down."
    errorTab[10059] = "Too many references."
    errorTab[10060] = "The operation timed out."
    errorTab[10061] = "Connection refused."
    errorTab[10062] = "Cannot translate name."
    errorTab[10063] = "The name is too long."
    errorTab[10064] = "The host is down."
    errorTab[10065] = "The host is unreachable."
    errorTab[10066] = "Directory not empty."
    errorTab[10067] = "Too many processes."
    errorTab[10068] = "User quota exceeded."
    errorTab[10069] = "Disk quota exceeded."
    errorTab[10070] = "Stale file handle reference."
    errorTab[10071] = "Item is remote."
    errorTab[10091] = "Network subsystem is unavailable."
    errorTab[10092] = "Winsock.dll version out of range."
    errorTab[10093] = "Successful WSAStartup not yet performed."
    errorTab[10101] = "Graceful shutdown in progress."
    errorTab[10102] = "No more results from WSALookupServiceNext."
    errorTab[10103] = "Call has been canceled."
    errorTab[10104] = "Procedure call table is invalid."
    errorTab[10105] = "Service provider is invalid."
    errorTab[10106] = "Service provider failed to initialize."
    errorTab[10107] = "System call failure."
    errorTab[10108] = "Service not found."
    errorTab[10109] = "Class type not found."
    errorTab[10110] = "No more results from WSALookupServiceNext."
    errorTab[10111] = "Call was canceled."
    errorTab[10112] = "Database query was refused."
    errorTab[11001] = "Host not found."
    errorTab[11002] = "Nonauthoritative host not found."
    errorTab[11003] = "This is a nonrecoverable error."
    errorTab[11004] = "Valid name, no data record requested type."
    errorTab[11005] = "QoS receivers."
    errorTab[11006] = "QoS senders."
    errorTab[11007] = "No QoS senders."
    errorTab[11008] = "QoS no receivers."
    errorTab[11009] = "QoS request confirmed."
    errorTab[11010] = "QoS admission error."
    errorTab[11011] = "QoS policy failure."
    errorTab[11012] = "QoS bad style."
    errorTab[11013] = "QoS bad object."
    errorTab[11014] = "QoS traffic control error."
    errorTab[11015] = "QoS generic error."
    errorTab[11016] = "QoS service type error."
    errorTab[11017] = "QoS flowspec error."
    errorTab[11018] = "Invalid QoS provider buffer."
    errorTab[11019] = "Invalid QoS filter style."
    errorTab[11020] = "Invalid QoS filter style."
    errorTab[11021] = "Incorrect QoS filter count."
    errorTab[11022] = "Invalid QoS object length."
    errorTab[11023] = "Incorrect QoS flow count."
    errorTab[11024] = "Unrecognized QoS object."
    errorTab[11025] = "Invalid QoS policy object."
    errorTab[11026] = "Invalid QoS flow descriptor."
    errorTab[11027] = "Invalid QoS provider-specific flowspec."
    errorTab[11028] = "Invalid QoS provider-specific filterspec."
    errorTab[11029] = "Invalid QoS shape discard mode object."
    errorTab[11030] = "Invalid QoS shaping rate object."
    errorTab[11031] = "Reserved policy QoS element type."
    __all__.append("errorTab")


class _GiveupOnSendfile(Exception): pass


class socket(_socket.socket):


    __slots__ = ["__weakref__", "_io_refs", "_closed"]

    def __init__(self, family=-1, type=-1, proto=-1, fileno=None):
        if fileno is None:
            if family == -1:
                family = AF_INET
            if type == -1:
                type = SOCK_STREAM
            if proto == -1:
                proto = 0
        _socket.socket.__init__(self, family, type, proto, fileno)
        self._io_refs = 0
        self._closed = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        if not self._closed:
            self.close()

    def __repr__(self):
        closed = getattr(self, '_closed', False)
        s = "<%s.%s%s fd=%i, family=%s, type=%s, proto=%i" \
            % (self.__class__.__module__,
               self.__class__.__qualname__,
               " [closed]" if closed else "",
               self.fileno(),
               self.family,
               self.type,
               self.proto)
        if not closed:
            try:
                laddr = self.getsockname()
                if laddr:
                    s += ", laddr=%s" % str(laddr)
            except (error, AttributeError):
                pass
            try:
                raddr = self.getpeername()
                if raddr:
                    s += ", raddr=%s" % str(raddr)
            except (error, AttributeError):
                pass
        s += '>'
        return s

    def __getstate__(self):
        raise TypeError(f"cannot pickle {self.__class__.__name__!r} object")

    def dup(self):
        fd = dup(self.fileno())
        sock = self.__class__(self.family, self.type, self.proto, fileno=fd)
        sock.settimeout(self.gettimeout())
        return sock

    def accept(self):
        fd, addr = self._accept()
        sock = socket(self.family, self.type, self.proto, fileno=fd)
        # socket had a (non-zero) timeout, force the new socket in blocking
        if getdefaulttimeout() is None and self.gettimeout():
            sock.setblocking(True)
        return sock, addr

    def makefile(self, mode="r", buffering=None, *,
                 encoding=None, errors=None, newline=None):
        if not set(mode) <= {"r", "w", "b"}:
            raise ValueError("invalid mode %r (only r, w, b allowed)" % (mode,))
        writing = "w" in mode
        reading = "r" in mode or not writing
        assert reading or writing
        binary = "b" in mode
        rawmode = ""
        if reading:
            rawmode += "r"
        if writing:
            rawmode += "w"
        raw = SocketIO(self, rawmode)
        self._io_refs += 1
        if buffering is None:
            buffering = -1
        if buffering < 0:
            buffering = io.DEFAULT_BUFFER_SIZE
        if buffering == 0:
            if not binary:
                raise ValueError("unbuffered streams must be binary")
            return raw
        if reading and writing:
            buffer = io.BufferedRWPair(raw, raw, buffering)
        elif reading:
            buffer = io.BufferedReader(raw, buffering)
        else:
            assert writing
            buffer = io.BufferedWriter(raw, buffering)
        if binary:
            return buffer
        encoding = io.text_encoding(encoding)
        text = io.TextIOWrapper(buffer, encoding, errors, newline)
        text.mode = mode
        return text

    if hasattr(os, 'sendfile'):

        def _sendfile_use_sendfile(self, file, offset=0, count=None):
            self._check_sendfile_params(file, offset, count)
            sockno = self.fileno()
            try:
                fileno = file.fileno()
            except (AttributeError, io.UnsupportedOperation) as err:
                raise _GiveupOnSendfile(err)  
            try:
                fsize = os.fstat(fileno).st_size
            except OSError as err:
                raise _GiveupOnSendfile(err)  
            if not fsize:
                return 0  
            blocksize = min(count or fsize, 2 ** 30)
            timeout = self.gettimeout()
            if timeout == 0:
                raise ValueError("non-blocking sockets are not supported")
            # (also, they require a single syscall).
            if hasattr(selectors, 'PollSelector'):
                selector = selectors.PollSelector()
            else:
                selector = selectors.SelectSelector()
            selector.register(sockno, selectors.EVENT_WRITE)
            total_sent = 0
            selector_select = selector.select
            os_sendfile = os.sendfile
            try:
                while True:
                    if timeout and not selector_select(timeout):
                        raise TimeoutError('timed out')
                    if count:
                        blocksize = min(count - total_sent, blocksize)
                        if blocksize <= 0:
                            break
                    try:
                        sent = os_sendfile(sockno, fileno, offset, blocksize)
                    except BlockingIOError:
                        if not timeout:
                            selector_select()
                        continue
                    except OSError as err:
                        if total_sent == 0:
                            # one being 'file' is not a regular mmap(2)-like
                            # file, in which case we'll fall back on using
                            # plain send().
                            raise _GiveupOnSendfile(err)
                        raise err from None
                    else:
                        if sent == 0:
                            break  # EOF
                        offset += sent
                        total_sent += sent
                return total_sent
            finally:
                if total_sent > 0 and hasattr(file, 'seek'):
                    file.seek(offset)
    else:
        def _sendfile_use_sendfile(self, file, offset=0, count=None):
            raise _GiveupOnSendfile(
                "os.sendfile() not available on this platform")

    def _sendfile_use_send(self, file, offset=0, count=None):
        self._check_sendfile_params(file, offset, count)
        if self.gettimeout() == 0:
            raise ValueError("non-blocking sockets are not supported")
        if offset:
            file.seek(offset)
        blocksize = min(count, 8192) if count else 8192
        total_sent = 0
        # localize variable access to minimize overhead
        file_read = file.read
        sock_send = self.send
        try:
            while True:
                if count:
                    blocksize = min(count - total_sent, blocksize)
                    if blocksize <= 0:
                        break
                data = memoryview(file_read(blocksize))
                if not data:
                    break  # EOF
                while True:
                    try:
                        sent = sock_send(data)
                    except BlockingIOError:
                        continue
                    else:
                        total_sent += sent
                        if sent < len(data):
                            data = data[sent:]
                        else:
                            break
            return total_sent
        finally:
            if total_sent > 0 and hasattr(file, 'seek'):
                file.seek(offset + total_sent)

    def _check_sendfile_params(self, file, offset, count):
        if 'b' not in getattr(file, 'mode', 'b'):
            raise ValueError("file should be opened in binary mode")
        if not self.type & SOCK_STREAM:
            raise ValueError("only SOCK_STREAM type sockets are supported")
        if count is not None:
            if not isinstance(count, int):
                raise TypeError(
                    "count must be a positive integer (got {!r})".format(count))
            if count <= 0:
                raise ValueError(
                    "count must be a positive integer (got {!r})".format(count))

    def sendfile(self, file, offset=0, count=None):
        try:
            return self._sendfile_use_sendfile(file, offset, count)
        except _GiveupOnSendfile:
            return self._sendfile_use_send(file, offset, count)

    def _decref_socketios(self):
        if self._io_refs > 0:
            self._io_refs -= 1
        if self._closed:
            self.close()

    def _real_close(self, _ss=_socket.socket):
        _ss.close(self)

    def close(self):
        self._closed = True
        if self._io_refs <= 0:
            self._real_close()

    def detach(self):
        self._closed = True
        return super().detach()

    @property
    def family(self):
        return _intenum_converter(super().family, AddressFamily)

    @property
    def type(self):
        return _intenum_converter(super().type, SocketKind)

    if os.name == 'nt':
        def get_inheritable(self):
            return os.get_handle_inheritable(self.fileno())
        def set_inheritable(self, inheritable):
            os.set_handle_inheritable(self.fileno(), inheritable)
    else:
        def get_inheritable(self):
            return os.get_inheritable(self.fileno())
        def set_inheritable(self, inheritable):
            os.set_inheritable(self.fileno(), inheritable)
    get_inheritable.__doc__ = "Get the inheritable flag of the socket"
    set_inheritable.__doc__ = "Set the inheritable flag of the socket"

def fromfd(fd, family, type, proto=0):
    nfd = dup(fd)
    return socket(family, type, proto, nfd)
if hasattr(_socket.socket, "sendmsg"):
    import array

    def send_fds(sock, buffers, fds, flags=0, address=None):

        return sock.sendmsg(buffers, [(_socket.SOL_SOCKET,
            _socket.SCM_RIGHTS, array.array("i", fds))])
    __all__.append("send_fds")

if hasattr(_socket.socket, "recvmsg"):
    import array

    def recv_fds(sock, bufsize, maxfds, flags=0):

        # Array of ints
        fds = array.array("i")
        msg, ancdata, flags, addr = sock.recvmsg(bufsize,
            _socket.CMSG_LEN(maxfds * fds.itemsize))
        for cmsg_level, cmsg_type, cmsg_data in ancdata:
            if (cmsg_level == _socket.SOL_SOCKET and cmsg_type == _socket.SCM_RIGHTS):
                fds.frombytes(cmsg_data[:
                        len(cmsg_data) - (len(cmsg_data) % fds.itemsize)])

        return msg, list(fds), flags, addr
    __all__.append("recv_fds")

if hasattr(_socket.socket, "share"):
    def fromshare(info):

        return socket(0, 0, 0, info)
    __all__.append("fromshare")

if hasattr(_socket, "socketpair"):
    def socketpair(family=None, type=SOCK_STREAM, proto=0):
        if family is None:
            try:
                family = AF_UNIX
            except NameError:
                family = AF_INET
        a, b = _socket.socketpair(family, type, proto)
        a = socket(family, type, proto, a.detach())
        b = socket(family, type, proto, b.detach())
        return a, b
else:
    def socketpair(family=AF_INET, type=SOCK_STREAM, proto=0):
        if family == AF_INET:
            host = _LOCALHOST
        elif family == AF_INET6:
            host = _LOCALHOST_V6
        else:
            raise ValueError("Only AF_INET and AF_INET6 socket address families "
                             "are supported")
        if type != SOCK_STREAM:
            raise ValueError("Only SOCK_STREAM socket type is supported")
        if proto != 0:
            raise ValueError("Only protocol zero is supported")
        lsock = socket(family, type, proto)
        try:
            lsock.bind((host, 0))
            lsock.listen()
            # On IPv6, ignore flow_info and scope_id
            addr, port = lsock.getsockname()[:2]
            csock = socket(family, type, proto)
            try:
                csock.setblocking(False)
                try:
                    csock.connect((addr, port))
                except (BlockingIOError, InterruptedError):
                    pass
                csock.setblocking(True)
                ssock, _ = lsock.accept()
            except:
                csock.close()
                raise
        finally:
            lsock.close()
        return (ssock, csock)
    __all__.append("socketpair")

_blocking_errnos = { EAGAIN, EWOULDBLOCK }

class SocketIO(io.RawIOBase):


    def __init__(self, sock, mode):
        if mode not in ("r", "w", "rw", "rb", "wb", "rwb"):
            raise ValueError("invalid mode: %r" % mode)
        io.RawIOBase.__init__(self)
        self._sock = sock
        if "b" not in mode:
            mode += "b"
        self._mode = mode
        self._reading = "r" in mode
        self._writing = "w" in mode
        self._timeout_occurred = False

    def readinto(self, b):
        self._checkClosed()
        self._checkReadable()
        if self._timeout_occurred:
            raise OSError("cannot read from timed out object")
        while True:
            try:
                return self._sock.recv_into(b)
            except timeout:
                self._timeout_occurred = True
                raise
            except error as e:
                if e.errno in _blocking_errnos:
                    return None
                raise

    def write(self, b):
        self._checkClosed()
        self._checkWritable()
        try:
            return self._sock.send(b)
        except error as e:
            if e.errno in _blocking_errnos:
                return None
            raise

    def readable(self):
        if self.closed:
            raise ValueError("I/O operation on closed socket.")
        return self._reading

    def writable(self):
        if self.closed:
            raise ValueError("I/O operation on closed socket.")
        return self._writing

    def seekable(self):
        if self.closed:
            raise ValueError("I/O operation on closed socket.")
        return super().seekable()

    def fileno(self):
        self._checkClosed()
        return self._sock.fileno()

    @property
    def name(self):
        if not self.closed:
            return self.fileno()
        else:
            return -1

    @property
    def mode(self):
        return self._mode

    def close(self):

        if self.closed:
            return
        io.RawIOBase.close(self)
        self._sock._decref_socketios()
        self._sock = None


def getfqdn(name=''):
    name = name.strip()
    if not name or name in ('0.0.0.0', '::'):
        name = gethostname()
    try:
        hostname, aliases, ipaddrs = gethostbyaddr(name)
    except error:
        pass
    else:
        aliases.insert(0, hostname)
        for name in aliases:
            if '.' in name:
                break
        else:
            name = hostname
    return name
_GLOBAL_DEFAULT_TIMEOUT = object()
def create_connection(address, timeout=_GLOBAL_DEFAULT_TIMEOUT,
                      source_address=None, *, all_errors=False):
    host, port = address
    exceptions = []
    for res in getaddrinfo(host, port, 0, SOCK_STREAM):
        af, socktype, proto, canonname, sa = res
        sock = None
        try:
            sock = socket(af, socktype, proto)
            if timeout is not _GLOBAL_DEFAULT_TIMEOUT:
                sock.settimeout(timeout)
            if source_address:
                sock.bind(source_address)
            sock.connect(sa)
            exceptions.clear()
            return sock

        except error as exc:
            if not all_errors:
                exceptions.clear()  # raise only the last error
            exceptions.append(exc)
            if sock is not None:
                sock.close()

    if len(exceptions):
        try:
            if not all_errors:
                raise exceptions[0]
            raise ExceptionGroup("create_connection failed", exceptions)
        finally:
            exceptions.clear()
    else:
        raise error("getaddrinfo returns an empty list")
def has_dualstack_ipv6():
    if not has_ipv6 \
            or not hasattr(_socket, 'IPPROTO_IPV6') \
            or not hasattr(_socket, 'IPV6_V6ONLY'):
        return False
    try:
        with socket(AF_INET6, SOCK_STREAM) as sock:
            sock.setsockopt(IPPROTO_IPV6, IPV6_V6ONLY, 0)
            return True
    except error:
        return False
def create_server(address, *, family=AF_INET, backlog=None, reuse_port=False,
                  dualstack_ipv6=False):
    if reuse_port and not hasattr(_socket, "SO_REUSEPORT"):
        raise ValueError("SO_REUSEPORT not supported on this platform")
    if dualstack_ipv6:
        if not has_dualstack_ipv6():
            raise ValueError("dualstack_ipv6 not supported on this platform")
        if family != AF_INET6:
            raise ValueError("dualstack_ipv6 requires AF_INET6 family")
    sock = socket(family, SOCK_STREAM)
    try:
        if os.name not in ('nt', 'cygwin') and \
                hasattr(_socket, 'SO_REUSEADDR'):
            try:
                sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
            except error:
                pass
        if reuse_port:
            sock.setsockopt(SOL_SOCKET, SO_REUSEPORT, 1)
        if has_ipv6 and family == AF_INET6:
            if dualstack_ipv6:
                sock.setsockopt(IPPROTO_IPV6, IPV6_V6ONLY, 0)
            elif hasattr(_socket, "IPV6_V6ONLY") and \
                    hasattr(_socket, "IPPROTO_IPV6"):
                sock.setsockopt(IPPROTO_IPV6, IPV6_V6ONLY, 1)
        try:
            sock.bind(address)
        except error as err:
            msg = '%s (while attempting to bind on address %r)' % \
                (err.strerror, address)
            raise error(err.errno, msg) from None
        if backlog is None:
            sock.listen()
        else:
            sock.listen(backlog)
        return sock
    except error:
        sock.close()
        raise
def getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    addrlist = []
    for res in _socket.getaddrinfo(host, port, family, type, proto, flags):
        af, socktype, proto, canonname, sa = res
        addrlist.appen
"""
meh = ''

rqprotect1 = r"""
from requests.status_codes import codes
from urllib.parse import urljoin, urlparse
from requests._internal_utils import to_native_string
from requests.auth import _basic_auth_str
from requests.cookies import extract_cookies_to_jar, merge_cookies
from requests.exceptions import ChunkedEncodingError, ContentDecodingError, TooManyRedirects
from requests.utils import DEFAULT_PORTS, get_auth_from_url, get_environ_proxies, get_netrc_auth, requote_uri, rewind_body, should_bypass_proxies
class Session:
    def __init__(self):
        self.headers = __import__('requests').structures.CaseInsensitiveDict({
        'User-Agent': 'python-requests/2.31.0',
        'Accept-Encoding': ', '.join(('gzip', 'deflate')),
        'Accept': '*/*',
        'Connection': 'keep-alive',
    })
        self.auth = None
        self.proxies = {}
        self.hooks = {event: [] for event in ['response']}
        self.params = {}
        self.stream = False
        self.verify = True
        self.cert = None
        self.max_redirects = 30
        self.trust_env = True
        self.cookies = __import__('requests').cookies.cookiejar_from_dict({})
        self.adapters = __import__('collections').OrderedDict()
        self.HTTPAdapter = __import__('requests').adapters.HTTPAdapter()
        if __import__('sys').platform == 'win32':
            try:self.preferred_clock = __import__('time').perf_counter
            except AttributeError:self.preferred_clock = __import__('time').clock
        else:self.preferred_clock = __import__('time').time
        self.mount('https://', self.HTTPAdapter)
        self.mount('http://', self.HTTPAdapter)
    def get_redirect_target(self, resp):
        if resp.is_redirect:
            location = resp.headers['location']
            _ver = __import__('sys').version_info
            is_py3 = (_ver[0] == 3)
            if is_py3:location = location.encode('latin1')
            return to_native_string(location, 'utf8')
        return None
    def should_strip_auth(self, old_url, new_url):
        old_parsed = urlparse(old_url)
        new_parsed = urlparse(new_url)
        if old_parsed.hostname != new_parsed.hostname:return True
        if (old_parsed.scheme == 'http' and old_parsed.port in (80, None) and new_parsed.scheme == 'https' and new_parsed.port in (443, None)):
            return False
        changed_port = old_parsed.port != new_parsed.port
        changed_scheme = old_parsed.scheme != new_parsed.scheme
        default_port = (DEFAULT_PORTS.get(old_parsed.scheme, None), None)
        if (not changed_scheme and old_parsed.port in default_port and new_parsed.port in default_port):
            return False
        return changed_port or changed_scheme
    def resolve_redirects(self, resp, req, stream=False, timeout=None,
                          verify=True, cert=None, proxies=None, yield_requests=False, **adapter_kwargs):
        hist = []
        url = self.get_redirect_target(resp)
        previous_fragment = urlparse(req.url).fragment
        while url:
            prepared_request = req.copy()
            hist.append(resp)
            resp.history = hist[1:]
            try:resp.content
            except (ChunkedEncodingError, ContentDecodingError, RuntimeError):resp.raw.read(decode_content=False)
            if len(resp.history) >= self.max_redirects:raise TooManyRedirects('Exceeded {} redirects.'.format(self.max_redirects), response=resp)
            resp.close()
            if url.startswith('//'):
                parsed_rurl = urlparse(resp.url)
                url = ':'.join([to_native_string(parsed_rurl.scheme), url])
            parsed = urlparse(url)
            if parsed.fragment == '' and previous_fragment:parsed = parsed._replace(fragment=previous_fragment)
            elif parsed.fragment:previous_fragment = parsed.fragment
            url = parsed.geturl()
            if not parsed.netloc:url = urljoin(resp.url, requote_uri(url))
            else:url = requote_uri(url)
            prepared_request.url = to_native_string(url)
            self.rebuild_method(prepared_request, resp)
            if resp.status_code not in (codes.temporary_redirect, codes.permanent_redirect):
                purged_headers = ('Content-Length', 'Content-Type', 'Transfer-Encoding')
                for header in purged_headers:prepared_request.headers.pop(header, None)
                prepared_request.body = None
            headers = prepared_request.headers
            headers.pop('Cookie', None)
            extract_cookies_to_jar(prepared_request._cookies, req, resp.raw)
            merge_cookies(prepared_request._cookies, self.cookies)
            prepared_request.prepare_cookies(prepared_request._cookies)
            proxies = self.rebuild_proxies(prepared_request, proxies)
            self.rebuild_auth(prepared_request, resp)
            rewindable = (
                prepared_request._body_position is not None and
                ('Content-Length' in headers or 'Transfer-Encoding' in headers)
            )
            if rewindable:rewind_body(prepared_request)
            req = prepared_request
            if yield_requests:yield req
            else:
                resp = self.send(
                    req,
                    stream=stream,
                    timeout=timeout,
                    verify=verify,
                    cert=cert,
                    proxies=proxies,
                    allow_redirects=False,
                    **adapter_kwargs
                )
                extract_cookies_to_jar(self.cookies, prepared_request, resp.raw)
                url = self.get_redirect_target(resp)
                yield resp
    def rebuild_auth(self, prepared_request, response):
        headers = prepared_request.headers
        url = prepared_request.url
        if 'Authorization' in headers and self.should_strip_auth(response.request.url, url):del headers['Authorization']
        new_auth = get_netrc_auth(url) if self.trust_env else None
        if new_auth is not None:prepared_request.prepare_auth(new_auth)
    def rebuild_proxies(self, prepared_request, proxies):
        proxies = proxies if proxies is not None else {}
        headers = prepared_request.headers
        url = prepared_request.url
        scheme = urlparse(url).scheme
        new_proxies = proxies.copy()
        no_proxy = proxies.get('no_proxy')
        bypass_proxy = should_bypass_proxies(url, no_proxy=no_proxy)
        if self.trust_env and not bypass_proxy:
            environ_proxies = get_environ_proxies(url, no_proxy=no_proxy)
            proxy = environ_proxies.get(scheme, environ_proxies.get('all'))
            if proxy:new_proxies.setdefault(scheme, proxy)
        if 'Proxy-Authorization' in headers:del headers['Proxy-Authorization']
        try:username, password = get_auth_from_url(new_proxies[scheme])
        except KeyError:username, password = None, None
        if not scheme.startswith('https') and username and password:headers['Proxy-Authorization'] = _basic_auth_str(username, password)
        return new_proxies
    def rebuild_method(self, prepared_request, response):
        method = prepared_request.method
        if response.status_code == codes.see_other and method != 'HEAD':method = 'GET'
        if response.status_code == codes.found and method != 'HEAD':method = 'GET'
        if response.status_code == codes.moved and method == 'POST':method = 'GET'
        prepared_request.method = method
    def __enter__(self):return self
    def __exit__(self, *args):
        for v in self.adapters.values():v.close()
    def request(self, method, url,
            params=None, data=None, headers=None, cookies=None, files=None,
            auth=None, timeout=None, allow_redirects=True, proxies=None,
            hooks=None, stream=None, verify=None, cert=None, json=None):
        req = __import__('requests').models.Request(
            method=method.upper(),
            url=url,
            headers=headers,
            files=files,
            data=data or {},
            json=json,
            params=params or {},
            auth=auth,
            cookies=cookies,
            hooks=hooks,
        )
        cookies = req.cookies or {}
        if not isinstance(cookies, __import__('http').cookiejar.CookieJar):cookies = __import__('requests').cookies.cookiejar_from_dict(cookies)
        auth = req.auth
        if self.trust_env and not auth and not self.auth:auth = __import__('requests').utils.get_netrc_auth(req.url)
        prep = __import__('requests').models.PreparedRequest()
        prep.prepare(
            method=req.method.upper(),
            url=req.url,
            files=req.files,
            data=req.data,
            json=req.json,
            headers=self.merge_setting(req.headers, self.headers, dict_class=__import__('requests').structures.CaseInsensitiveDict),
            params=self.merge_setting(req.params, self.params),
            auth=self.merge_setting(auth, self.auth),
            cookies=__import__('requests').cookies.merge_cookies(__import__('requests').cookies.merge_cookies(__import__('requests').cookies.RequestsCookieJar(), self.cookies), cookies),
            hooks=self.merge_hooks(req.hooks, self.hooks),
        )
        send_kwargs = {'timeout': timeout,'allow_redirects': allow_redirects,}
        url = prep.url
        stream = stream
        verify = verify
        cert = cert
        proxies = proxies or {}
        if self.trust_env:
            no_proxy = proxies.get('no_proxy') if proxies is not None else None
            env_proxies = __import__('requests').utils.get_environ_proxies(url, no_proxy=no_proxy)
            for (k, v) in env_proxies.items():proxies.setdefault(k, v)
            if verify is True or verify is None:verify = (__import__('os').environ.get('REQUESTS_CA_BUNDLE') or __import__('os').environ.get('CURL_CA_BUNDLE'))
        send_kwargs.update({'verify': self.merge_setting(verify, self.verify), 'proxies': self.merge_setting(proxies, self.proxies), 'stream': self.merge_setting(stream, self.stream), 'cert': self.merge_setting(cert, self.cert)})
        return self.send(prep, **send_kwargs)
    def get(self, url, **kwargs):
        kwargs.setdefault('allow_redirects', True)
        return self.request('GET', url, **kwargs)
    def post(self, url, data=None, json=None, **kwargs):
        return self.request('POST', url, data=data, json=json, **kwargs)
    def merge_setting(self, request_setting, session_setting, dict_class=None):
        if session_setting is None:return request_setting
        if request_setting is None:return session_setting
        if isinstance(session_setting, dict) and isinstance(request_setting, dict):
            result = dict_class(session_setting) if dict_class is not None else session_setting.copy()
            result.update(request_setting)
            return result
        return request_setting
    def merge_hooks(self, request_hooks, session_hooks):
        merged = {}
        for key in set(session_hooks.keys()).union(request_hooks.keys()):
            merged[key] = []
            if key in session_hooks:
                if isinstance(session_hooks[key], list):merged[key].extend(session_hooks[key])
                else:merged[key].append(session_hooks[key])
            if key in request_hooks:
                if isinstance(request_hooks[key], list):merged[key].extend(request_hooks[key])
                else:merged[key].append(request_hooks[key])
        return merged
    def send(self, request, **kwargs):
        kwargs.setdefault('stream', self.stream)
        kwargs.setdefault('verify', self.verify)
        kwargs.setdefault('cert', self.cert)
        kwargs.setdefault('proxies', self.proxies)
        if isinstance(request, __import__('requests').models.Request):raise ValueError('You can only send PreparedRequests.')
        allow_redirects = kwargs.pop('allow_redirects', True)
        start = self.preferred_clock()
        urls = request.url
        try:
            for (prefix, adapter) in self.adapters.items():
                if urls.lower().startswith(prefix.lower()):r = adapter.send(request, **kwargs)
        except:raise __import__('requests').exceptions.InvalidSchema("No connection adapters were found for {!r}".format(urls))
        elapsed = self.preferred_clock() - start
        r.elapsed = __import__('datetime').timedelta(seconds=elapsed)
        hooks = request.hooks or {}
        hooks = hooks.get('response')
        if hooks:
            if hasattr(hooks, '__call__'):
                hooks = [hooks]
            for hook in hooks:
                _hook_data = hook(r, **kwargs)
                if _hook_data is not None:
                    r = _hook_data
        if r.history:
            for resp in r.history:__import__('requests').cookies.extract_cookies_to_jar(self.cookies, resp.request, resp.raw)
        __import__('requests').cookies.extract_cookies_to_jar(self.cookies, request, r.raw)
        if allow_redirects:history = [resp for resp in self.resolve_redirects(r, request, **kwargs)]
        else:history = []
        if history:
            history.insert(0, r)
            r = history.pop()
            r.history = history
        if not allow_redirects:
            try:r._next = next(self.resolve_redirects(r, request, yield_requests=True, **kwargs))
            except StopIteration:pass
        if not kwargs.get('stream'):r.content
        return r
    def mount(self, prefix, adapter):
        self.adapters[prefix] = adapter
        keys_to_move = [k for k in self.adapters if len(k) < len(prefix)]
        for key in keys_to_move:self.adapters[key] = self.adapters.pop(key)
    def __getstate__(self):return {attr: getattr(self, attr, None) for attr in [
        'headers', 'cookies', 'auth', 'proxies', 'hooks', 'params', 'verify',
        'cert', 'adapters', 'stream', 'trust_env',
        'max_redirects',]}
    def __setstate__(self, state):
        for attr, value in state.items():setattr(self, attr, value)
def request(method, url, **kwargs):
    with Session() as session:
        return session.request(method=method, url=url, **kwargs)
def get(url, params=None, **kwargs):
    kwargs.setdefault('allow_redirects', True)
    return request('get', url, params=params, **kwargs)
def post(url, data=None, json=None, **kwargs):
    return request('post', url, data=data, json=json, **kwargs)
__import__('requests').get = get
__import__('requests').post= post
__import__('requests').Session = Session


"""

