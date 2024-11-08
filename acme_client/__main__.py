import argparse
import sys
from http.server import HTTPServer
from threading import Thread
from dnslib.server import DNSServer

from acme_client.http01_handler import HTTP01Handler
from acme_client.dns01_handler import DNS01Handler
from acme_client.ACME_Client import ACME_Clients
from acme_client.ShutdownHandler import ShutdownHandler


if __name__ == "__main__":
    # Hint: You may want to start by parsing command line arguments and
    # perform some sanity checks first. The built-in `argparse` library will suffice.
    parser = argparse.ArgumentParser(description="ACME Client")
    parser.add_argument("Challenge_type", choices=["dns01", "http01"], required=True)
    parser.add_argument("--dir", required=True)
    parser.add_argument("--record", required=True)
    parser.add_argument("--domain", required=True, action="append")

    arguments = parser.parse_args()

    shutdown_server = HTTPServer(("0.0.0.0", 5003), ShutdownHandler)
    shutdown_thread = Thread(target=shutdown.serve_forever)
    shutdown_thread.daemon = True



    http01_server = HTTPServer(("0.0.0.0", 5002), HTTP01Handler)
    dns01_server = DNSServer(DNS01Handler(), port=10053, address="0.0.0.0")
    # Hint: You will need more HTTP servers

    http01_thread = Thread(target = http01_server.serve_forever)
    dns01_thread = Thread(target = dns01_server.server.serve_forever)
    http01_thread.daemon = True
    dns01_thread.daemon = True

    shutdown_thread.start()
    http01_thread.start()
    dns01_thread.start()

    # Your code should go here
    acme_client = ACME_Client(dir_url=arguments.dir)
    acme_client.register_account()
    order_response = acme_client.post_new_order(arguments.domain)

    authorizations = order_response.json().get("authorizations")
    if not authorizations:
        print("no authorizations")
    
    for url in authorizations:
        acme_client.solve_challenges(url)
    
    acme_client.poll_for_status(order_response.headers.get("Location"), "ready")
    finalize_req = acme_client.finalize(order_response.json())
    acme_client.poll_for_status(order_response.headers.get("Location"), "valid")

    


