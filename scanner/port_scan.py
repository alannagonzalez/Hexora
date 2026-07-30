import socket
import time


COMMON_PORTS = {

    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP Proxy",
    8443: "HTTPS Alt"

}



def scan_ports(domain):

    results = []


    try:

        ip_address = socket.gethostbyname(domain)


        for port, service in COMMON_PORTS.items():


            start_time = time.time()


            try:

                with socket.socket(
                    socket.AF_INET,
                    socket.SOCK_STREAM
                ) as sock:


                    sock.settimeout(1.5)


                    connection = sock.connect_ex(
                        (ip_address, port)
                    )



                    response_time = round(
                        (time.time() - start_time) * 1000,
                        2
                    )



                    if connection == 0:

                        status = "Abierto"

                    else:

                        status = "Cerrado"



                    results.append({

                        "port": port,

                        "service": service,

                        "status": status,

                        "response_time": f"{response_time} ms"

                    })



            except socket.timeout:

                results.append({

                    "port": port,

                    "service": service,

                    "status": "Timeout",

                    "response_time": "N/A"

                })


        return results



    except socket.gaierror:

        return {

            "error": "No se pudo resolver el dominio."

        }


    except Exception as error:

        return {

            "error": str(error)

        }