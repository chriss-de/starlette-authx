from starlette.types import Receive, Scope, Send
import ipaddress
from . import merge_auth_info


def validate_config(config):
    # valid networks?
    pass


async def process(config, scope: Scope, receive: Receive, send: Send) -> None:
    client_networks = []
    client_ip_address = ipaddress.ip_address(scope['client'][0])

    for ip_access in config:
        for ip_address in config[ip_access]:
            if client_ip_address in ipaddress.ip_interface(ip_address).network:
                client_networks.append(ip_access)

    if len(client_networks) > 0:
        merge_auth_info(scope, {'ipaccess': set(client_networks)})
