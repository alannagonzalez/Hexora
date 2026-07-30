def check_security_headers(headers):

    # Normalizar headers
    normalized_headers = {
        key.lower(): value
        for key, value in headers.items()
    }


    security_checks = {

        "strict-transport-security": {

            "check": "HSTS",

            "status": "OK",

            "message": "HSTS está configurado",

            "warning": "HSTS no encontrado"

        },


        "x-frame-options": {

            "check": "Clickjacking Protection",

            "status": "OK",

            "message": "X-Frame-Options encontrado",

            "warning": "X-Frame-Options no encontrado"

        }

    }


    results = []


    for header, info in security_checks.items():


        if header in normalized_headers:


            results.append({

                "check": info["check"],

                "status": info["status"],

                "message": info["message"]

            })


        else:


            results.append({

                "check": info["check"],

                "status": "WARNING",

                "message": info["warning"]

            })



    # ==========================
    # Content Security Policy
    # ==========================

    csp = normalized_headers.get(
        "content-security-policy"
    )

    csp_report = normalized_headers.get(
        "content-security-policy-report-only"
    )



    if csp_report:


        results.append({

            "check": "CSP",

            "status": "INFO",

            "message":
                "CSP encontrada en modo Report-Only. "
                "La política está en monitoreo pero no aplica restricciones activas."

        })



    elif csp:


        results.append({

            "check": "CSP",

            "status": "OK",

            "message":
                "Content-Security-Policy activo"

        })



    else:


        results.append({

            "check": "CSP",

            "status": "WARNING",

            "message":
                "CSP no encontrado"

        })


    return results