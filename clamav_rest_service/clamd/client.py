"""Client for clamd.

It comes in two shapes:
 - ClamdUnixSocket for clamav daemon running locally
 - ClamdTCPSocket for clamav daemon on the network

Once connection is established, the behaviour is the same.

"""
import abc
import logging
import re
import struct
import socket
import typing as t

from .types import ClamdException, \
    ClamdScanResult, \
    ClamdScanStatus, \
    ClamdCmdResponse

scan_status_line_pattern = re.compile(r"^(.+?):\s+(.+)?\s?(OK|FOUND|ERROR)$")


class Clamd(abc.ABC):
    """Abstract client for clamd daemon.
    """
    def __init__(self, cmd_terminator: bytes, buffer_size: int):
        self.cmd_terminator = cmd_terminator
        self.buffer_size = buffer_size

        # cmd specifier is a prefix we put before the command.  Its
        # value is 'z' for null terminated commands or 'n' for newline
        # terminated commands.  Read more in man clamd(8)
        if cmd_terminator == b'\x00':
            self.cmd_specifier = b'z'
        elif cmd_terminator == b'\n':
            self.cmd_specifier = b'n'
        else:
            raise ClamdException("Unknown command terminator, "
                                 "\\x00 or \\n accepted."
                                 "Read man clamd(8) for details")
        self._sock = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *args, **kwargs):
        self.close()
        return False

    def connect(self) -> None:
        """Connect to clamd daemon.
        """
        self._sock = self._get_connection()

    def close(self) -> None:
        """Close connection to clamd daemon.
        """
        self._sock.close()

    def ping(self) -> ClamdCmdResponse:
        """Execute clamd PING command.

        Check the server's state. It should reply with "PONG".
        """
        return self._simple_command("PING")

    def version(self) -> ClamdCmdResponse:
        """Execute clamd VERSION command.

        Print program and database versions.
        """
        return self._simple_command("VERSION")

    def stats(self) -> ClamdCmdResponse:
        """Execute clamd STATS command.

        Replies with statistics about the scan queue, contents of scan
        queue, and memory usage.
        """
        return self._simple_command("STATS")

    def scan(self, filepath: str) -> ClamdScanResult:
        """Execute clamd SCAN command.

        Scan a file or a directory (recursively) with archive support
        enabled (if not disabled in clamd.conf). A full path is
        required.

        :param filepath: Path of the file to scan
        :return: Result of the scanning as ClamdScanResult instance
        """
        self._send_command(f"SCAN {filepath}")
        recd_raw = self._recv()
        return self._parse_scan_result(recd_raw)

    def instream(self, input_stream: t.IO[bytes]) -> ClamdScanResult:
        """Execute clamd INSTREAM command.

        Scan a stream of data. The stream is sent to clamd in chunks,
        after INSTREAM, on the same socket on which the command was
        sent.  This avoids the overhead of establishing new TCP
        connections and problems with NAT.

        :param input_stream: Input stream to analyze
        :return: Result of the scanning as ClamdScanResult instance
        """
        self._send_command_streaming("INSTREAM", input_stream)
        recd_raw = self._recv()
        return self._parse_scan_result(recd_raw)

    # TODO implement SESSION workflow with these methods and dedicated class
    #
    # def idsession(self) -> str:
    #     """Execute IDSESSION clamd command.

    #     Start a clamd session. Within a session multiple SCAN,
    #     INSTREAM, FILDES, VERSION, STATS commands can be sent on the
    #     same socket without opening new connections.
    #     """
    #     return self._simple_command("IDSESSION")

    # def end(self) -> str:
    #     """Execute IDSESSION clamd command.

    #     End a clamd session. Within a session multiple SCAN,
    #     INSTREAM, FILDES, VERSION, STATS commands can be sent on the
    #     same socket without opening new connections.
    #     """
    #     return self._simple_command("END")

    @abc.abstractmethod
    def _get_connection(self) -> socket.socket:
        """Get connection to clamd as socket.

        :return: Socket connected to clamd
        """

    def _simple_command(self, command: str) -> ClamdCmdResponse:
        """Send simple command to clamd and wait for response.

        :param command: Command to execute, possible values in man clamd(8)
        :return: clamd command response
        """
        self._send_command(command)
        recd_raw = self._recv()
        return self._parse_response(recd_raw)

    def _send_command(self, command: str) -> None:
        """Send command to clamd.

        :param command: Command to execute, possible values in man clamd(8)
        """
        full_cmd = b''.join([
            self.cmd_specifier,
            command.encode(),
            self.cmd_terminator,
        ])
        logging.debug("Sending command: %s", full_cmd)
        self._sock.send(full_cmd)

    def _recv(self) -> str:
        """Receive response from clamd socket.

        :return: Raw data received (UTF-8)
        """
        # block until we receive everything from daemon
        recd_data = bytearray()
        recd_buf = self._sock.recv(self.buffer_size)
        while recd_buf:
            recd_data.extend(recd_buf)
            recd_buf = self._sock.recv(self.buffer_size)

        return recd_data.decode()

    def _send_command_streaming(self,
                                command: str,
                                input_stream: t.IO[bytes]) -> None:
        """Send a command streaming content to clamd.

        :param command: Command to send
        :input_stream: Input stream to send chunked to clamd
        """
        self._send_command(command)

        # for packing the chunk we prepend the length of chunk data in a
        # 4-byte integer, so we can read 4 bytes less from the input stream
        read_buf_size = self.buffer_size - 4

        # send stream of packets
        buf = input_stream.read(read_buf_size)
        while buf:
            buflen = len(buf)
            # pack buf as man clamd(8) says for INSTREAM command
            chunk = struct.pack('!L{}s'.format(buflen), buflen, buf)
            self._sock.send(chunk)
            buf = input_stream.read(read_buf_size)

        # TODO: when we reach the StreamMaxLength, clamd should reply
        # with "INSTREAM size limit exceeded". What actually happens,
        # though, is that we get a broken pipe. This case is pretty
        # common and has to be handled!

        # send an empty buffer to signal that we are finished
        self._sock.send(struct.pack('!L', 0))

    def _parse_response(self, raw_resp: str) -> ClamdCmdResponse:
        """Parse a generic clamd response to a command.

        :param raw_resp: Raw clamd response string
        :return: Structured response object
        """
        # split lines using cmd terminator (clamd respects the
        # terminator that we chose)
        raw_resp_lines = raw_resp.split(self.cmd_terminator.decode())
        message = raw_resp_lines[0]
        additional_lines = raw_resp_lines[1:]

        # remove ''
        additional_lines = [al for al in additional_lines if al]

        return ClamdCmdResponse(
            raw_data=raw_resp,
            message=message,
            details=additional_lines,
        )

    def _parse_scan_result(self, raw_resp: str) -> ClamdScanResult:
        """Parse a scanning command response.

        :param raw_resp: Raw clamd response string
        :return: Structured scan result
        """
        resp = self._parse_response(raw_resp)

        # parse the main line (message)
        m = scan_status_line_pattern.match(resp.message)
        if not m:
            # not able to parse correctly clamd response
            return ClamdScanResult(
                input_file=None,
                raw_data=raw_resp,
                message=resp.message,
                status=ClamdScanStatus.CLIENT_PARSE_ERROR,
                virus=None,
                err_msg="Unable to parse clamd response",
                details=resp.details,
            )

        input_file = m.group(1)
        msg = (m.group(2) or "").strip()
        status = ClamdScanStatus(m.group(3))

        match status:
            case ClamdScanStatus.OK:
                virus = None
                err_msg = None
            case ClamdScanStatus.FOUND:
                # msg contains virus
                virus = msg
                err_msg = None
            case ClamdScanStatus.ERROR:
                # msg contains error message
                virus = None
                err_msg = msg

        return ClamdScanResult(
            input_file=input_file,
            raw_data=raw_resp,
            message=resp.message,
            status=status,
            virus=virus,
            err_msg=err_msg,
            details=resp.details,
        )


class ClamdUnixSocket(Clamd):
    """Client for clamd daemon over UNIX domain socket.

    This is the recommended option when clamd is running on the same host.

    When using this option, clamd should be running with 'LocalSocket <path>'
    configuration option in clamd.conf (see man clamd.conf(5)).
    """
    def __init__(self,
                 socket_path: str,
                 timeout: int = 300,  # seconds
                 cmd_terminator: bytes = b'\x00',
                 buffer_size: int = 2048):
        """Create clamd client instance for UNIX domain socket.

        :param socket_path: Path of the clamd daemon socket
        :param timeout: Timeout of the socket
        :param cmd_terminator: Terminator of clamd commands
        :param buffer_size: Size of the buffer to read/write to clamd
        """
        super().__init__(cmd_terminator=cmd_terminator,
                         buffer_size=buffer_size)
        self.socket_path = socket_path
        self.timeout = timeout

    def _get_connection(self) -> socket.socket:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect(self.socket_path)
        except FileNotFoundError:
            raise ClamdException("clamd unix socket not found at " +
                                 self.socket_path +
                                 ". Is the clamd daemon running?")
        return sock


class ClamdTCPSocket(Clamd):
    """Client for clamd daemon over TCP socket.

    This is the recommended (only) option when clamd is running on
    other host in the network.

    When using this option, clamd should be running with 'TCPSocket <port>'
    configuration option in clamd.conf (see man clamd.conf(5)).
    """
    def __init__(self,
                 host: str,
                 port: int,
                 timeout: int = 300,  # seconds
                 cmd_terminator: bytes = b'\x00',
                 buffer_size: int = 1024):
        """Create clamd client instance for TCP socket.

        :param host: TCP host
        :param port: TCP port
        :param timeout: Timeout of the socket
        :param cmd_terminator: Terminator of clamd commands
        :param buffer_size: Size of the buffer to read/write to clamd
        """
        super().__init__(cmd_terminator=cmd_terminator,
                         buffer_size=buffer_size)
        self.host = host
        self.port = port
        self.timeout = timeout

    def _get_connection(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setdefaulttimeout(self.timeout)
        sock.connect((self.host, self.port))
        return sock
