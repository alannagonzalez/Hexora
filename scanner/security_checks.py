
def check_security_headers(headers):

    security_checks = {
        "Strict-Transport-Security": {
            "check": "HSTS",
            "status": "OK",
            "message": "HSTS está configurado",
            "warning": "HSTS no encontrado"
        },
        "X-Frame-Options": {
            "check": "Clickjacking Protection",
            "status": "OK",
            "message": "X-Frame-Options encontrado",
            "warning": "X-Frame-Options no encontrado"
        }
    }

    results = []

    for header, info in security_checks.items():

        if header in headers:
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

    csp = headers.get("Content-Security-Policy")
    csp_report = headers.get("Content-Security-Policy-Report-Only")

    if csp_report:
        results.append({
            "check": "CSP",
            "status": "WARNING",
            "message": "CSP encontrado en modo Report-Only"
        })

    elif csp:
        results.append({
            "check": "CSP",
            "status": "OK",
            "message": "Content-Security-Policy activo"
        })

    else:
        results.append({
            "check": "CSP",
            "status": "WARNING",
            "message": "CSP no encontrado"
        })

    return results