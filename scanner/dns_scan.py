#Archivo para el analisis DNS de la URL

import socket
from urllib.parse import urlparse


def get_domain_ip(url):
    try:
        parsed_url = urlparse(url)

        domain = parsed_url.netloc

        ip_address = socket.gethostbyname(domain)

        return {
            "domain": domain,
            "ip": ip_address
        }

    except socket.gaierror:
        return {
            "error": "No fue posible resolver el dominio.",
            "domain": None,
            "ip": None
        }

    except Exception as error:
        return {
            "error": str(error),
            "domain": None,
            "ip": None
        }