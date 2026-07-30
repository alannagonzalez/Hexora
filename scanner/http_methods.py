import requests


def check_http_methods(url):

    results = []

    methods_to_check = [
        "PUT",
        "DELETE",
        "TRACE"
    ]

    try:

        for method in methods_to_check:

            try:

                response = requests.request(
                    method,
                    url,
                    timeout=5,
                    allow_redirects=True
                )

                status_code = response.status_code

                if status_code in (200, 201, 202, 204):

                    results.append({
                        "method": method,
                        "status": "WARNING",
                        "message": (
                            f"Método {method} permitido "
                            f"(HTTP {status_code})."
                        )
                    })

                elif status_code in (401, 403):

                    results.append({
                        "method": method,
                        "status": "OK",
                        "message": (
                            f"Método {method} bloqueado "
                            f"(HTTP {status_code})."
                        )
                    })

                elif status_code in (404, 405):

                    results.append({
                        "method": method,
                        "status": "OK",
                        "message": (
                            f"Método {method} no permitido "
                            f"(HTTP {status_code})."
                        )
                    })

                elif status_code >= 500:

                    results.append({
                        "method": method,
                        "status": "INFO",
                        "message": (
                            f"No fue posible verificar el método {method} "
                            f"porque el servidor respondió con HTTP {status_code}."
                        )
                    })

                else:

                    results.append({
                        "method": method,
                        "status": "INFO",
                        "message": (
                            f"Respuesta inesperada para {method}: "
                            f"HTTP {status_code}."
                        )
                    })

            except requests.exceptions.RequestException:

                results.append({
                    "method": method,
                    "status": "INFO",
                    "message": (
                        f"No fue posible comprobar el método {method}."
                    )
                })

        return results

    except Exception as error:

        return {
            "error": str(error)
        }