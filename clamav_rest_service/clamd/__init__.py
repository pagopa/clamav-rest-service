"""Python bindings for clamd daemon on Unix or TCP socket.

For details about commands, see man clamd(8).

Usage:
.. code-block:: python

    with ClamdUnixSocket("/var/run/clamd.sock) as clamd:
        scan = clamd.scan("/my/file.txt")

Open and close connection each time you run a command.
For example:
.. code-block:: python

    with ClamdUnixSocket("/var/run/clamd.sock) as clamd:
        ping = clamd.ping()

    with ClamdUnixSocket("/var/run/clamd.sock) as clamd:
        scan = clamd.scan("/my/file.txt")

NOTE: clamd sessions are yet not implemented.

"""

from .types import ClamdScanStatus, ClamdScanResult, ClamdException  # noqa
from .client import Clamd, ClamdUnixSocket, ClamdTCPSocket  # noqa
