import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from decimal import Decimal
from getpass import getpass
from http.client import HTTPConnection, HTTPException
from ipaddress import IPv4Address
from queue import Full, Queue
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.parse import parse_qsl, urlencode, urlsplit
from urllib.request import Request, urlopen
from zoneinfo import ZoneInfo

def parse_measurement(form):
    measured = int(form["meastime"])
    if not 631065600 <= measured <= time.time() + 86400:
        raise ValueError("invalid measurement timestamp")

    values = {}
    for item in json.loads(form["measures"])["measures"]:
        kind, value, exponent = (int(item[key]) for key in ("type", "value", "unit"))
        if not -9 <= exponent <= 9:
            raise ValueError("invalid measurement exponent")
        values[kind] = float(Decimal(value).scaleb(exponent))

    weight = values[1]
    if not 0 < weight < 500:
        raise ValueError("invalid weight")
    return measured, weight


WITHINGS_HOST = "scalews.withings.net"
PUBLIC_DNS_URL = "https://cloudflare-dns.com/dns-query"
HOP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade",
}


def end_to_end_headers(headers):
    excluded = HOP_HEADERS | {"content-length"}
    for value in headers.get_all("Connection", []):
        excluded.update(name.strip().lower() for name in value.split(","))
    return [(name, value) for name, value in headers.items() if name.lower() not in excluded]


def resolve_withings():
    query = urlencode({"name": WITHINGS_HOST, "type": "A"})
    request = Request(f"{PUBLIC_DNS_URL}?{query}", headers={"Accept": "application/dns-json"})
    relay_ips = {os.getenv("BIND_IP"), os.getenv("LISTEN_IP")}
    with urlopen(request, timeout=5) as response:
        result = json.load(response)
    if result.get("Status") == 0:
        for answer in result.get("Answer", []):
            if answer.get("type") == 1:
                address = IPv4Address(answer["data"])
                if address.is_global and not address.is_multicast and str(address) not in relay_ips:
                    return str(address)
    raise ValueError("public DNS returned no usable Withings A record")


class ScaleHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = 10

    def setup(self):
        super().setup()
        self.upstream = HTTPConnection(self.server.upstream_ip, 80, timeout=8)

    def finish(self):
        self.upstream.close()
        super().finish()

    def relay(self):
        try:
            if not self.path.startswith("/") or self.path.startswith("//"):
                raise ValueError("expected an origin-form request target")
            lengths = self.headers.get_all("Content-Length", [])
            size = int(lengths[0]) if lengths else 0
            if (len(lengths) > 1 or self.headers.get("Transfer-Encoding")
                    or not 0 <= size <= 65536):
                raise ValueError("unsupported request framing")
            raw = self.rfile.read(size)
            if len(raw) != size:
                raise ValueError("incomplete request")
        except (ValueError, OSError):
            self.send_error(400)
            return

        if self.server.log_raw:
            logging.info("Scale %s %s %r", self.command, self.path, raw)
        try:
            self.upstream.putrequest(self.command, self.path, skip_host=True,
                                     skip_accept_encoding=True)
            self.upstream.putheader("Host", WITHINGS_HOST)
            for name, value in end_to_end_headers(self.headers):
                if name.lower() != "host":
                    self.upstream.putheader(name, value)
            if lengths:
                self.upstream.putheader("Content-Length", str(size))
            self.upstream.endheaders(raw)
            response = self.upstream.getresponse()
        except (HTTPException, OSError, ValueError) as error:
            logging.warning("Withings relay failed (%s)", type(error).__name__)
            self.upstream.close()
            self.send_error(502)
            return

        try:
            with response:
                self.relay_response(response)
        except (HTTPException, OSError) as error:
            logging.warning("Withings response interrupted (%s)", type(error).__name__)
            self.upstream.close()
            self.close_connection = True
            return
        if (200 <= response.status < 300 and self.command == "POST"
                and urlsplit(self.path).path == "/cgi-bin/measure"):
            self.mirror(raw)

    def relay_response(self, response):
        status = response.status
        no_body = self.command == "HEAD" or status in (204, 304)
        chunked = not no_body and (response.chunked or response.length is None)
        self.send_response_only(status, response.reason)
        for name, value in end_to_end_headers(response.headers):
            self.send_header(name, value)
        if chunked:
            self.send_header("Transfer-Encoding", "chunked")
        elif no_body:
            length = response.headers.get("Content-Length")
            if length is not None and status != 204:
                self.send_header("Content-Length", length)
        else:
            self.send_header("Content-Length", str(response.length))
        self.end_headers()

        if not no_body:
            while chunk := response.read1(65536):
                if chunked:
                    self.wfile.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
                else:
                    self.wfile.write(chunk)
            if response.length not in (0, None):
                raise HTTPException("incomplete Withings response")
            if chunked:
                self.wfile.write(b"0\r\n\r\n")
        self.wfile.flush()
        self.log_request(status)

    do_GET = do_HEAD = do_POST = relay

    def mirror(self, raw):
        settings = self.server
        if settings.uploads is None:
            return
        try:
            form = dict(parse_qsl(raw.decode("ascii"), keep_blank_values=True,
                                  max_num_fields=128))
            if form.get("action") != "store":
                return
            user = form.get("userid")
            if user and settings.user_id:
                matches_user = user == settings.user_id
            else:
                matches_user = settings.single_user
            if not matches_user:
                logging.info("Skipped Garmin upload for an unmatched scale user")
                return
            settings.uploads.put_nowait(parse_measurement(form))
        except Full:
            logging.warning("Garmin upload queue full, skipped weigh-in")
        except (KeyError, TypeError, ValueError, OverflowError):
            logging.warning("Could not parse scale weight for Garmin")


def upload_pending(uploads, uploader):
    while True:
        uploader(*uploads.get())


class GarminUploader:
    def __init__(self, zone, token_json):
        self.zone = zone
        self.token_json = token_json
        self.client = None

    def __call__(self, measured, weight):
        from garminconnect import Garmin

        try:
            if self.client is None:
                client = Garmin()
                client.login(self.token_json)
                self.client = client

            utc = datetime.fromtimestamp(measured, timezone.utc)
            local = utc.astimezone(self.zone)
            self.client.add_weigh_in_with_timestamps(
                weight, unitKey="kg",
                dateTimestamp=local.replace(tzinfo=None).isoformat(timespec="milliseconds"),
                gmtTimestamp=utc.replace(tzinfo=None).isoformat(timespec="milliseconds"),
            )
        except Exception as error:
            logging.warning("Garmin upload failed (%s)", type(error).__name__)
            return False

        logging.info("Uploaded weigh-in to Garmin")
        return True


def serve():
    capture = os.getenv("SCALE_CAPTURE", "0") == "1"
    try:
        upstream_ip = resolve_withings()
    except (OSError, ValueError) as error:
        raise SystemExit(f"Could not resolve {WITHINGS_HOST} via public DNS: {error}") from None
    logging.info("Resolved Withings upstream %s to %s", WITHINGS_HOST, upstream_ip)
    user_id = os.getenv("SCALE_USER_ID", "")
    single_user = os.getenv("SCALE_SINGLE_USER", "0") == "1"
    if not capture and not (user_id or single_user):
        raise ValueError("Set SCALE_USER_ID or enable SCALE_SINGLE_USER for Garmin uploads")
    zone = ZoneInfo(os.getenv("SCALE_TIMEZONE", "America/Los_Angeles"))
    bind = os.getenv("LISTEN_IP", "0.0.0.0")
    port = int(os.getenv("PORT", "8080"))
    with ThreadingHTTPServer((bind, port), ScaleHandler) as server:
        server.upstream_ip = upstream_ip
        server.user_id = user_id
        server.single_user = single_user
        server.log_raw = os.getenv("LOG_RAW", "0") == "1"
        server.uploads = None
        if not capture:
            token_json = os.getenv("GARMIN_TOKEN_JSON", "").strip()
            try:
                if not isinstance(json.loads(token_json), dict):
                    raise ValueError
            except ValueError:
                raise SystemExit("Set GARMIN_TOKEN_JSON to the Garmin token JSON object.") from None
            server.uploads = Queue(maxsize=32)
            uploader = GarminUploader(zone, token_json)
            Thread(target=upload_pending, args=(server.uploads, uploader), daemon=True).start()
        logging.info("Listening on port %s for WBS01 requests", server.server_port)
        server.serve_forever()


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    os.environ.pop("GARMINTOKENS", None)
    if sys.argv[1:] == ["login"]:
        from garminconnect import Garmin

        client = Garmin(
            email=input("Garmin email: ").strip(),
            password=getpass("Garmin password: "),
            prompt_mfa=lambda: input("Garmin MFA code: ").strip(),
        )
        client.login()
        print(client.client.dumps())
    elif not sys.argv[1:]:
        serve()
    else:
        raise SystemExit("Usage: python bridge.py [login]")


if __name__ == "__main__":
    main()
