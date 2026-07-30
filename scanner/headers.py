
#headers scan
import requests
def scan_headers(url):
    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True
        )

        return {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "final_url": response.url
        }

    except requests.exceptions.Timeout:
        return {
            "error": "Tiempo de espera agotado."
        }

    except requests.exceptions.ConnectionError:
        return {
            "error": "No se pudo conectar con el sitio."
        }

    except Exception as error:
        return {
            "error": str(error)
        }