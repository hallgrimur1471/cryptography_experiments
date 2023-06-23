"""
Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection
"""


import os
import time
import logging
import threading
import random
import json
from base64 import b64encode, b64decode
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from urllib.request import urlopen
from urllib.error import HTTPError

import drvn.cryptography.math as math
import drvn.cryptography.aes as aes
import drvn.cryptography.sha as sha

import requests


class NodeA:
    def __init__(self):
        self.keep_running = True
        self.b_url = "http://localhost:40002"

        self.http_server = HTTPServer(("", 40001), ARequestHandler)
        self.http_server.timeout = 1.0
        self.server_thread = threading.Thread(target=self.serve_http)
        logging.info("Starting A's HTTP server ...")
        self.server_thread.start()

    def serve_http(self):
        while self.keep_running:
            self.http_server.handle_request()

    def stop(self):
        self.keep_running = False

    def run_protocol_sequence(self):
        p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF
        g = 2
        a = random.randint(0, p - 1)
        A = math.modexp(g, a, p)

        r = requests.post(
            self.b_url,
            json={"msg_num": 1, "p": p, "g": g, "A": A},
        )
        node_b_reply = json.loads(r.text)
        logging.info(
            "A got reply from B:\n" + json.dumps(node_b_reply, indent=2)
        )
        B = node_b_reply["B"]

        s = math.modexp(B, a, p)
        key = sha.sha1(s.to_bytes((s.bit_length() + 7) // 8, "big"))[0:16]
        iv = os.urandom(16)
        ciphertext = aes.encrypt_cbc(
            b"The cryptopals crypto challenges", key, iv
        )
        r = requests.post(
            self.b_url,
            json={
                "msg_num": 2,
                "ciphertext_b64": b64encode(ciphertext).decode(),
                "iv_b64": b64encode(iv).decode(),
            },
        )
        node_b_reply = json.loads(r.text)
        logging.info(
            "A got reply from B:\n" + json.dumps(node_b_reply, indent=2)
        )
        ciphertext_from_node_b = b64decode(node_b_reply["ciphertext_b64"])
        iv_from_node_b = b64decode(node_b_reply["iv_b64"])
        plaintext_from_node_b = aes.decrypt_cbc(
            ciphertext_from_node_b, key, iv_from_node_b
        )
        logging.info(
            f"B decrypted message from A: '{plaintext_from_node_b.decode()}'"
        )


class ARequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = 0
        if "Content-Length" in self.headers:
            content_length = int(self.headers["Content-Length"])
        body = self.rfile.read(content_length)

        logging.info(
            "A received POST request:\n"
            + json.dumps(json.loads(body), indent=2)
        )

        self.send_response(200)
        self.end_headers()
        self.wfile.write(
            b"A Received POST request with body:\n"
            + json.dumps(json.loads(body), indent=2)
            + b"\n"
        )

    # silence logging
    def log_message(self, format, *args):  # pylint:disable=redefined-builtin
        return


class NodeB:
    def __init__(self):
        BRequestHandler.node = self
        self.http_server = HTTPServer(("", 40002), BRequestHandler)
        self.http_server.timeout = 1.0
        self.server_thread = threading.Thread(target=self.serve_http)
        self.keep_running = True
        logging.info("Starting B's HTTP server ...")
        self.server_thread.start()

    def serve_http(self):
        while self.keep_running:
            self.http_server.handle_request()

    def stop(self):
        self.keep_running = False


class BRequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = 0
        if "Content-Length" in self.headers:
            content_length = int(self.headers["Content-Length"])
        body = self.rfile.read(content_length)

        logging.info(
            "B received POST request:\n"
            + json.dumps(json.loads(body), indent=2)
        )

        data = json.loads(body)
        if data["msg_num"] == 1:
            self.handle_msg_num_1(data)
        elif data["msg_num"] == 2:
            self.handle_msg_num_2(data)
        else:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(
                b"B Received bad request with body: " + body + b"\n"
            )

    def handle_msg_num_1(self, data):
        p = int(data["p"])
        g = int(data["g"])
        A = int(data["A"])

        b = random.randint(0, p - 1)
        B = math.modexp(g, b, p)

        s = math.modexp(A, b, p)
        BRequestHandler.node.key = sha.sha1(
            s.to_bytes((s.bit_length() + 7) // 8, "big")
        )[0:16]

        self.send_response(200)
        self.end_headers()
        self.wfile.write(json.dumps({"B": B}).encode())

    def handle_msg_num_2(self, data):
        ciphertext = b64decode(data["ciphertext_b64"])
        iv = b64decode(data["iv_b64"])

        key = BRequestHandler.node.key
        plaintext = aes.decrypt_cbc(ciphertext, key, iv)
        logging.info(f"B decrypted message from A: '{plaintext.decode()}'")

        new_iv = os.urandom(16)
        new_ciphertext = aes.encrypt_cbc(plaintext, key, new_iv)

        self.send_response(200)
        self.end_headers()
        self.wfile.write(
            json.dumps(
                {
                    "ciphertext_b64": b64encode(new_ciphertext).decode(),
                    "iv_b64": b64encode(new_iv).decode(),
                }
            ).encode()
        )

    # silence logging
    def log_message(self, format, *args):  # pylint:disable=redefined-builtin
        return


class NodeM:
    def __init__(self):
        self.http_server = HTTPServer(("", 40003), MRequestHandler)
        self.http_server.timeout = 1.0
        self.server_thread = threading.Thread(target=self.serve_http)
        self.keep_running = True
        logging.info("Starting M's HTTP server ...")
        self.server_thread.start()

    def serve_http(self):
        while self.keep_running:
            self.http_server.handle_request()

    def stop(self):
        self.keep_running = False


class MRequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = 0
        if "Content-Length" in self.headers:
            content_length = int(self.headers["Content-Length"])
        body = self.rfile.read(content_length)

        logging.info("M received POST request: " + body.decode())

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"M Received POST request with body: " + body + b"\n")

    # silence logging
    def log_message(self, format, *args):  # pylint:disable=redefined-builtin
        return


def run_challenge():
    a = NodeA()
    b = NodeB()
    m = NodeM()

    a.run_protocol_sequence()

    # logging.info("Sleeping for 1 seconds ...")
    # time.sleep(1)
    logging.info("Stopping HTTP servers ...")
    for node in [a, b, m]:
        node.stop()
