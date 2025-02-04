import io
import os
from clamav_rest_service.clamd import ClamdUnixSocket, ClamdScanStatus


# require running clamd daemon

def test_cmd_ping():
    with ClamdUnixSocket(socket_path="/tmp/clamd.sock") as clamd:
        pong = clamd.ping()

    assert pong.raw_data == "PONG\x00"
    assert pong.message == "PONG"
    assert not pong.details


def test_cmd_version():
    with ClamdUnixSocket("/tmp/clamd.sock") as clamd:
        version = clamd.version()

    assert version.message.startswith("ClamAV 1.4.2")
    assert not version.details


def test_cmd_stats():
    with ClamdUnixSocket("/tmp/clamd.sock") as clamd:
        stats = clamd.stats()

    assert stats.message.startswith("POOLS: ")
    assert "THREADS: " in stats.message
    assert "QUEUE: " in stats.message
    assert "MEMSTATS: " in stats.message
    assert stats.message.endswith("END")
    assert not stats.details


def test_cmd_scanfile():
    with ClamdUnixSocket("/tmp/clamd.sock") as clamd:
        testfile = os.path.abspath("tests/assets/testfile.txt")
        result = clamd.scan(testfile)

    assert result
    assert result.input_file == testfile
    assert result.virus is None
    assert result.status == ClamdScanStatus.OK


def test_cmd_scanfile_errnotfound():
    with ClamdUnixSocket("/tmp/clamd.sock") as clamd:
        # FIXME absolute path
        testfile = "/this/does/not/exist"
        result = clamd.scan(testfile)

    assert result
    assert result.input_file == testfile
    assert result.status == ClamdScanStatus.ERROR
    assert result.virus is None
    assert result.err_msg == "File path check failure: No such file or directory."


def test_cmd_scanfile_large():
    with ClamdUnixSocket("/tmp/clamd.sock") as clamd:
        testfile = os.path.abspath("tests/assets/testfile_112M_random")
        result = clamd.scan(testfile)

    assert result
    assert result.input_file == testfile
    assert result.virus is None
    assert result.status == ClamdScanStatus.OK


def test_cmd_instream():
    with ClamdUnixSocket("/tmp/clamd.sock") as clamd:
        testfile = os.path.abspath("tests/assets/testfile.txt")
        stream = open(testfile, "rb")
        result = clamd.instream(stream)

    assert result
    assert result.input_file == "stream"
    assert result.virus is None
    assert result.status == ClamdScanStatus.OK


def test_cmd_instream_large():
    with ClamdUnixSocket("/tmp/clamd.sock") as clamd:
        # FIXME absolute path
        testfile = os.path.abspath("tests/assets/testfile_112M_random")
        stream = open(testfile, "rb")
        result = clamd.instream(stream)

    assert result
    assert result.input_file == "stream"
    assert result.virus is None
    assert result.status == ClamdScanStatus.OK


def test_cmd_instream_infected():
    with ClamdUnixSocket("/tmp/clamd.sock") as clamd:
        infected = br"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        stream = io.BytesIO(infected)
        result = clamd.instream(stream)

    assert result
    assert result.input_file == "stream"
    assert result.virus == "Win.Test.EICAR_HDB-1"
    assert result.status == ClamdScanStatus.FOUND
