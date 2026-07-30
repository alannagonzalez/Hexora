# headers scan

import requests


def scan_headers(url):

    try:

        response = requests.get(
            url,
            timeout=15,
            allow_redirects=True,
            headers={
                "User-Agent": "Mozilla/5.0 Hexora Security Scanner"
            }
        )


        return {

            "status_code": response.status_code,

            "headers": dict(response.headers),

            "final_url": response.url

        }


    except requests.exceptions.Timeout:

        return {

            "error":
            "El servidor tardó demasiado en responder."

        }


    except requests.exceptions.ConnectionError:

        return {

            "error":
            "No fue posible establecer conexión con el servidor."

        }


    except requests.exceptions.RequestException as error:

        return {

            "error":
            f"Error HTTP durante el análisis: {str(error)}"

        }


    except Exception as error:

        return {

            "error":
            str(error)

        }