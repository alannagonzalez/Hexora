import socket
import ssl
from datetime import datetime


def get_ssl_info(domain):

    try:

        ssl_context = ssl.create_default_context()


        with socket.create_connection(
            (domain, 443),
            timeout=5
        ) as connection:


            with ssl_context.wrap_socket(
                connection,
                server_hostname=domain
            ) as secure_socket:


                certificate = secure_socket.getpeercert()



        expiration_date = datetime.strptime(
            certificate["notAfter"],
            "%b %d %H:%M:%S %Y %Z"
        )


        current_date = datetime.now()


        days_remaining = (
            expiration_date - current_date
        ).days



        if expiration_date < current_date:

            status = "Certificado vencido"


        elif days_remaining <= 30:

            status = "Certificado próximo a vencer"


        else:

            status = "Certificado válido"



        issuer = ", ".join(
            value
            for item in certificate.get("issuer", [])
            for _, value in item
        )


        subject = ", ".join(
            value
            for item in certificate.get("subject", [])
            for _, value in item
        )


        return {

            "status": status,

            "expires": expiration_date.strftime(
                "%d/%m/%Y %H:%M:%S"
            ),

            "days_remaining": days_remaining,

            "issuer": issuer,

            "subject": subject

        }



    except ssl.SSLCertVerificationError:

        return {
            "error": "El certificado SSL no pudo ser validado."
        }


    except socket.timeout:

        return {
            "error": "Tiempo de espera agotado al conectar con el certificado SSL."
        }


    except socket.gaierror:

        return {
            "error": "No se pudo resolver el dominio."
        }


    except Exception as error:

        return {
            "error": str(error)
        }