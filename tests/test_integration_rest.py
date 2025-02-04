import io

from werkzeug.datastructures import FileStorage


def test_ping(client):
    resp = client.get("/api/v1/clamav/ping")

    assert resp.status_code == 200
    resp_d = resp.json
    assert resp_d["status"] == "OK"
    assert resp_d["message"] == "PONG"


def test_clamav_version(client):
    resp = client.get("/api/v1/clamav/version")

    assert resp.status_code == 200
    resp_d = resp.json
    assert resp_d["message"].startswith("ClamAV 1.4.2")


def test_stats(client):
    resp = client.get("/api/v1/clamav/stats")

    assert resp.status_code == 200
    resp_d = resp.json
    assert resp_d["message"].startswith("POOLS: ")
    assert resp_d["message"].endswith("END")


def test_scan(client):
    file_to_analyze = FileStorage(
        stream=open("tests/assets/testfile.txt", "rb"),
        filename="testfile.txt"
    )

    resp = client.post("/api/v1/clamav/scan",
                       data={"file": file_to_analyze},
                       content_type="multipart/form-data")

    assert resp.status_code == 200
    resp_d = resp.json

    assert resp_d["status"] == "OK"
    assert resp_d["virus"] is None
    assert resp_d["error"] is None
    assert not resp_d["details"]


def test_scan_large(client):
    file_to_analyze = FileStorage(
        stream=open("tests/assets/testfile_112M_random", "rb"),
        filename="testfile.txt"
    )

    resp = client.post("/api/v1/clamav/scan",
                       data={"file": file_to_analyze},
                       content_type="multipart/form-data")

    assert resp.status_code == 200
    resp_d = resp.json

    assert resp_d["status"] == "OK"
    assert resp_d["virus"] is None
    assert resp_d["error"] is None
    assert resp_d["input_file"] == "testfile.txt"
    assert not resp_d["details"]


def test_scan_infected(client):
    infected = br"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    file_to_analyze = FileStorage(
        stream=io.BytesIO(infected),
        filename="infected"
    )

    resp = client.post("/api/v1/clamav/scan",
                       data={"file": file_to_analyze},
                       content_type="multipart/form-data")

    assert resp.status_code == 200
    resp_d = resp.json

    assert resp_d["status"] == "FOUND"
    assert resp_d["virus"] == "Win.Test.EICAR_HDB-1"
    assert resp_d["input_file"] == "infected"
    assert "raw_data" not in resp_d
    assert not resp_d["details"]
