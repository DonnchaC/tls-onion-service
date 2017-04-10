#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Make a existing local or ephemeral hidden service available over TLS for non-Tor users
"""

import os
import sys
import time
import logging
import argparse
import subprocess
from multiprocessing import Process
import ssl

from flask import Flask, send_from_directory
from stem.control import Controller

handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter(fmt="%(asctime)s [%(levelname)s]: %(message)s"))

logger = logging.getLogger(__name__)
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)

app = Flask(__name__)


def make_directory(path):
    if not os.path.exists(path):
        os.makedirs(path)


@app.route("/")
def index():
    return "It works"


@app.route("/<path:filename>")
def serve_challenge_response(filename):
    """Serve files from the web root directory"""
    return send_from_directory(app.config["web_root"], filename)


def request_cert(domain, web_root, data_dir, testing=False):
    """Run cerbot in background to issue a new cert"""
    cmd = [
        "certbot", "certonly", "--webroot", "-d", domain, "--register-unsafely-without-email",
        "--work-dir", data_dir, "--config-dir", data_dir, "--logs-dir", data_dir, "--agree-tos",
        "-w", web_root, "--keep",
    ]
    if testing:
        cmd.append("--test-cert")

    logger.debug("Running: {}".format(" ".join(cmd)))
    return subprocess.check_output(cmd, stderr=subprocess.STDOUT)


def create_server_thread(*args, **kwargs):
    return Process(target=app.run, kwargs=kwargs)


def server_with_letsencrypt_keys(port, cert_path):
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.load_cert_chain(os.path.join(cert_path, "fullchain.pem"),
                            os.path.join(cert_path, "privkey.pem"))
    return create_server_thread(port=port, ssl_context=context)

def start_ephemeral_onion(ports):
    """
    Start ephemeral onion address and wait for publication.

    The ports argument should be a dictionary mapping public to local ports
    """
    with Controller.from_port() as controller:
        controller.authenticate()
        return controller.create_ephemeral_hidden_service(ports, await_publication=True,
                                                          detached=True)


def parse_cmd_args():
    """Parses and returns command line arguments."""
    parser = argparse.ArgumentParser(description="%s start a Flask web server and request"
                                     "a LetsEncrypt cert for your onion address." % sys.argv[0])

    parser.add_argument("--onion_address", type=str, default=None,
                        help="Local onion service address. If not provided an ephemeral onion "
                        "service will be started.")

    parser.add_argument("--proxy-host", type=str, default="oniongate.com",
                        help="Service running the OnionGateway TLS proxy (default: '%(default)s').")

    parser.add_argument("--http-port", type=int, default=8080,
                        help="Local destination port for HTTP request to the Tor "
                        "onion service (default: '%(default)s').")

    parser.add_argument("--tls-port", "-p", type=int, default=8443,
                        help="Local destination port for TLS connections to the Tor "
                        "onion service (default: '%(default)s').")

    parser.add_argument("--letsencrypt-data-dir", "-d", type=str, default="letsencrypt_data",
                        help="Directory to store LetsEncrypt keys, logs and other data "
                        "(default: '%(default)s').")

    parser.add_argument("--web-root", "-w", type=str, default="webroot",
                        help="Directory to store LetsEncrypt challenges (default: '%(default)s').")

    parser.add_argument("--test-run", action="store_true",
                        help="Use the LetsEncrypt staging server when requesting the cert.")

    # parser.add_argument("--challenge-path", type=str, default="/.well-known/acme-challenge/",
    #                     help="The path where LetsEncrypt challenges are served "
    #                     "(default: '%(default)s').")

    return parser.parse_args()


def main():
    args = parse_cmd_args()

    make_directory(args.web_root)
    app.config["web_root"] = args.web_root

    # Start an ephemeral onion if no onion address is provided.
    if not args.onion_address:
        logger.info("Starting ephemeral onion service, this may take a minute...")
        response = start_ephemeral_onion({80: args.http_port, 443: args.tls_port})
        onion_address = response.service_id
        logger.info("Started ephemeral onion service {}".format(onion_address))

    else:
        onion_address = args.onion_address

    if onion_address.endswith(".onion"):
        onion_address = onion_address[:-6]

    # Determine public domain from onion address and proxy host
    domain = ".".join([onion_address, args.proxy_host])

    # Start a local Flask server to serve the LetsEncrypt challenge response
    # The `adhoc` ssl_context mode creates a temporary self-signed cert and private key
    logger.info("Starting Flask server with self-signed certs for domain {}".format(domain))
    server = create_server_thread(port=args.tls_port, ssl_context="adhoc")
    server.start()
    time.sleep(5)

    try:
        logger.info("Starting LetsEncrypt cert request")
        certbot_response = request_cert(domain, args.web_root, args.letsencrypt_data_dir,
                                        args.test_run)
        logger.debug("Certbot output:\n{}".format(certbot_response.decode("utf-8")))

    except subprocess.CalledProcessError as e:
        logger.warning("LetsEncrypt cert issuance failed:\n{}".format(e.output.decode("utf-8")))
        server.terminate()
        sys.exit(1)

    # Stop running Flask server and restart with the new certs
    logger.info("Successfully got a LetsEncrypt cert for https://{}".format(domain))
    server.terminate()
    server.join()

    logger.info("Starting Flask server with the LetsEncrypt certificate")
    cert_path = os.path.join(args.letsencrypt_data_dir, "live", domain)
    server = server_with_letsencrypt_keys(port=args.tls_port, cert_path=cert_path)
    server.daemon = True
    server.start()

    # Start the HTTP server for direct connections to the onion address
    app.run(port=args.http_port)

if __name__ == "__main__":
    main()
