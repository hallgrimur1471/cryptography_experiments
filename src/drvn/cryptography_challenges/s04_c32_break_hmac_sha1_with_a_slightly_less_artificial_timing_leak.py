"""
Break HMAC-SHA1 with a slightly less artificial timing leak
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
        assert "/" not in file_
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
        for i, _ in enumerate(signature):
            measurements = dict()
            tries = 0
            while True:
                tries += 1
                print(f"z_test round {tries}")
                rounds = 10
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

                for b, ts in list(measurements.items()):
                    s = statistics.stdev(ts)
                    u = statistics.mean(ts)
                    ts_no_outliers = []
                    cut = 1
                    for t in ts:
                        z_score = (t - u) / s
                        if abs(z_score) <= cut:
                            ts_no_outliers.append(t)
                    measurements[b] = ts_no_outliers

                means = [statistics.mean(ts) for _, ts in measurements.items()]
                p_mean = statistics.mean(means)
                p_stdev = statistics.stdev(means)

                z_scores = [(x - p_mean) / p_stdev for x in means]
                z_scores.sort(reverse=True)

                # less than 99.7% of samples nomral distribution have stdev >= 3
                outlier_cutoff = 3
                # the longer we try the min_dist is reduced
                min_dist_from_next = 3 - ((tries - 1) / 10)
                if (
                    z_scores[0] >= outlier_cutoff
                    and z_scores[0] - z_scores[1] >= min_dist_from_next
                ):
                    break

            stats = list(measurements.items())
            stats.sort(key=lambda s: statistics.mean(s[1]), reverse=True)

            print()
            for b, ts in reversed(stats):
                mean_ts = statistics.mean(ts)
                z_score = (mean_ts - p_mean) / p_stdev
                b_hex = b.to_bytes(1, byteorder="little").hex()
                print(f"{b_hex}: ", end="")
                for t in sorted(ts):
                    print(f"{t:.5f} ", end="")
                print(" " * ((tries * rounds) - len(ts)) * 8, end="")
                print(f"-> | mean={mean_ts:.5f} | z_score={z_score:.5f} |")

            deduced_byte = stats[0][0]
            signature[i] = deduced_byte
            print("correct:        9de535f8463657127b5f734cac3e0900d408dc78")
            progress = (i + 1) / len(signature) * 100
            print(f"deduced [{progress:3.0f}%]: {signature.hex()[0:(2*(i+1))]}")

            correct_hex = "9de535f8463657127b5f734cac3e0900d408dc78"
            assert (
                signature.hex()[0 : (2 * (i + 1))]
                == correct_hex[0 : (2 * (i + 1))]
            )

        logging.info(
            f"Resulting signature from timing attack:\n{signature.hex()}"
        )
        logging.info("Opening file with signature ...")
        results = urlopen(
            f"http://localhost:1471/test?file={file_}&signature={signature.hex()}"
        )
        print(results.read())

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
    for i in range(max(len(a), len(b))):
        if i >= len(a) or i >= len(b) or a[i] != b[i]:
            return False
        # Challenge 31 failed with sleep of 0.00125
        # so this challenge we will try to break with sleep <= 0.00125
        # The solution to this challenge has been tested to work with sleep = 0.00025
        time.sleep(0.00025)
    return True
