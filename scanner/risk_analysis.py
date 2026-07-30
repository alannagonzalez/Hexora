def calculate_risk(
    vulnerabilities,
    port_results=None,
    ssl_info=None,
    status_code=None
):

    score = 100
    details = []

    severity_points = {
        "CRITICO": 25,
        "ALTO": 15,
        "MEDIO": 10,
        "BAJO": 2,
        "INFO": 0
    }

    for vulnerability in vulnerabilities:

        severity = vulnerability.get(
            "severity",
            "BAJO"
        ).upper()

        points = severity_points.get(
            severity,
            0
        )

        score -= points

        details.append({
            "severity": severity,
            "message": vulnerability.get(
                "message",
                "Vulnerabilidad detectada."
            ),
            "impact": -points
        })

    if port_results:

        for port in port_results:

            port_number = port.get("port")
            status = port.get("status")

            if (
                port_number == 21 and
                status == "Abierto"
            ):

                details.append({
                    "severity": "INFO",
                    "message": "Puerto FTP abierto. Verificar si el servicio es necesario.",
                    "impact": 0
                })

            elif (
                port_number == 23 and
                status == "Abierto"
            ):

                score -= 15

                details.append({
                    "severity": "ALTO",
                    "message": "Puerto Telnet abierto. Se recomienda deshabilitarlo.",
                    "impact": -15
                })

            elif (
                port_number == 3389 and
                status == "Abierto"
            ):

                score -= 5

                details.append({
                    "severity": "BAJO",
                    "message": "Puerto RDP expuesto públicamente.",
                    "impact": -5
                })

            elif (
                port_number == 8080 and
                status == "Abierto"
            ):

                details.append({
                    "severity": "INFO",
                    "message": "Puerto 8080 abierto. Verificar si el servicio es necesario.",
                    "impact": 0
                })

    if ssl_info:

        ssl_status = ssl_info.get("status")

        if ssl_status == "Certificado vencido":

            score -= 20

            details.append({
                "severity": "ALTO",
                "message": "Certificado SSL vencido.",
                "impact": -20
            })

        elif ssl_status == "Certificado próximo a vencer":

            score -= 5

            details.append({
                "severity": "BAJO",
                "message": "Certificado SSL próximo a vencer.",
                "impact": -5
            })

    if status_code and status_code >= 500:

        details.append({
            "severity": "INFO",
            "message": "El servidor respondió con un error HTTP 5xx. Algunos resultados podrían no ser precisos.",
            "impact": 0
        })

    score = max(0, min(score, 100))

    if score >= 90:
        level = "EXCELENTE"

    elif score >= 75:
        level = "BUENO"

    elif score >= 50:
        level = "MEDIO"

    elif score >= 25:
        level = "ALTO"

    else:
        level = "CRITICO"

    return {
        "score": score,
        "level": level,
        "details": details
    }