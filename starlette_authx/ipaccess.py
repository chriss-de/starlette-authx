from starlette.types import Receive, Scope, Send
import ipaddress
from typing import List


def process(config, scope: Scope, receive: Receive, send: Send) -> List:
    client_networks = []
    client_ip_address = ipaddress.ip_address(scope['client'][0])

    for ip_access in config:
        for ip_address in config[ip_access]:
            if client_ip_address in ipaddress.ip_interface(ip_address).network:
                client_networks.append(ip_access)

    return set(client_networks)
