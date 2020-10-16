"""
Implement and break HMAC-SHA1 with an artificial timing leak
"""

import time
import logging
import threading
import statistics
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from urllib.request import urlopen
from urllib.error import HTTPError

import drvn.cryptography.utils as utils
import drvn.cryptography.hmac as hmac


def run_challenge():
    http_server = HTTPServer(("", 1471), RequestHandler)
    server_thread = threading.Thread(target=http_server.serve_forever)
    logging.info("Starting HTTP server ...")
    server_thread.start()

    try:
        time.sleep(1)

        file_ = "README.md"
        signature = utils.generate_random_bytes(20)  # guess
        logging.info("Trying signature ")
        try:
            urlopen(
                f"http://localhost:1471/test?file={file_}&signature={signature.hex()}"
            )
        except HTTPError:
            logging.info("Signature failed")

        logging.info("Comencing timing attack ...")
        signature = bytearray(signature)
        signature[0] = int("9d", 16)  # TODO: remove
        signature[1] = int("e5", 16)  # TODO: remove
        signature[2] = int("35", 16)  # TODO: remove
        signature[3] = int("f8", 16)  # TODO: remove
        signature[4] = int("46", 16)  # TODO: remove
        signature[5] = int("36", 16)  # TODO: remove
        signature[6] = int("57", 16)  # TODO: remove
        rounds = 5
        for i, _ in enumerate(signature):
            if i <= 6:  # TODO: remove
                continue  # TODO: remove
            measurements = dict()
            for r in range(rounds):
                for b in range(256):
                    signature[i] = b
                    t = measure_time(file_, signature)

                    if not b in measurements:
                        measurements[b] = []
                    measurements[b].append(t)

                    print(
                        f"    {(r*255 + b) / (rounds*255) * 100:.2f}%\r",
                        end="",
                        flush=True,
                    )

            stats = list(measurements.items())
            stats.sort(key=lambda s: min(s[1]), reverse=True)

            print()
            for b, ts in reversed(stats):
                min_ts = min(ts)
                b_hex = b.to_bytes(1, byteorder="little").hex()
                print(f"{b_hex}: ", end="")
                for t in sorted(ts):
                    print(f"{t:.5f} ", end="")
                print(f"-> {min_ts}")

            deduced_byte = stats[0][0]
            signature[i] = deduced_byte
            print("correct:        9de535f8463657127b5f734cac3e0900d408dc78")
            progress = i / len(signature) * 100
            print(f"deduced [{progress:3.0f}%]: {signature.hex()[0:(2*(i+1))]}")

        logging.info(
            f"Resulting signature from timing attack:\n{signature.hex()}"
        )
        logging.info("Opening file with signature ...")
        results = urlopen(
            f"http://localhost:1471/test?file={file_}&signature={signature.hex()}"
        )
        print(results)

    finally:
        logging.info("Shutting down HTTP server ...")
        http_server.shutdown()


def measure_time(file_, signature):
    try:
        start_time = time.time()
        urlopen(
            f"http://localhost:1471/test?file={file_}&signature={signature.hex()}"
        )
    except HTTPError:
        logging.debug("Signature failed")
    finally:
        end_time = time.time()

    return end_time - start_time


class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        results = urlparse(self.path)
        query = parse_qs(results.query)

        file_, signature = query["file"][0], query["signature"][0]
        file_ = file_.encode()
        signature = bytes.fromhex(signature)

        if is_authenticated(file_, signature):
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            file_contents = Path(file_.decode()).read_bytes()
            self.wfile.write(file_contents)
        else:
            self.send_response(403)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"Not authenticated to view file\n")

    # silence logging
    def log_message(self, format, *args):  # pylint:disable=redefined-builtin
        return


def is_authenticated(file_, signature):
    key = b"very secret key"
    hmac_ = hmac.sha1(key, file_)
    return insecure_compare(signature, hmac_)


def insecure_compare(a, b):
    """
    Insecure method for checking if a equals b

    Args:
        a (bytes)
        b (bytes)
    """
    # print("comparing")
    # print(f"{a=}")
    # print(f"{b=}")
    for i in range(max(len(a), len(b))):
        if i >= len(a) or i >= len(b) or a[i] != b[i]:
            return False
        time.sleep(0.05)
    return True
