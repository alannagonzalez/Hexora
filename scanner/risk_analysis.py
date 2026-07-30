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

            "title": vulnerability.get(
                "title",
                vulnerability.get(
                    "message",
                    "Vulnerabilidad detectada."
                )
            ),

            "description": vulnerability.get(
                "description",
                ""
            ),

            "impact": vulnerability.get(
                "impact",
                f"Impacto asociado a severidad {severity}."
            ),

            "recommendation": vulnerability.get(
                "recommendation",
                ""
            ),

            "score_impact": -points

        })




    if port_results:

        for port in port_results:


            port_number = port.get("port")

            status = port.get("status")



            if (
                port_number == 21 and
                status == "Abierto"
            ):

                score -= 5
                details.append({
                    "severity": "BAJO",
                    "title": "Puerto FTP expuesto",
                    "description":
                    "Se detectó un servicio FTP accesible desde Internet.",
                    "impact":
                    "Puede permitir transferencia de archivos si el servicio no está correctamente protegido.",
                    "recommendation":
                    "Deshabilitar FTP si no es necesario o utilizar SFTP."

            })



            elif (
                port_number == 8080 and
                status == "Abierto"
            ):


                details.append({
                    "severity": "INFO",
                    "title": "Puerto HTTP alternativo expuesto",
                    "description":
                    "Se detectó un servicio HTTP alternativo accesible desde Internet.",
                    "impact":
                    "Debe validarse que el servicio expuesto corresponda a una aplicación autorizada.",
                    "recommendation":
                    "Confirmar que el servicio esté correctamente configurado y protegido."

                })



            elif (
                port_number == 23 and
                status == "Abierto"
            ):


                score -= 15


                details.append({

                    "severity": "ALTO",

                    "title":
                    "Puerto Telnet abierto",

                    "description":
                    "El servicio Telnet está disponible públicamente.",

                    "impact":
                    "Telnet transmite información sin cifrado.",

                    "recommendation":
                    "Deshabilitar Telnet y utilizar SSH.",

                    "score_impact": -15

                })



            elif (
                port_number == 3389 and
                status == "Abierto"
            ):


                score -= 5


                details.append({

                    "severity": "BAJO",

                    "title":
                    "Puerto RDP expuesto",

                    "description":
                    "El servicio Remote Desktop está accesible desde Internet.",

                    "impact":
                    "Puede aumentar la superficie de ataque.",

                    "recommendation":
                    "Restringir acceso mediante VPN o reglas firewall.",

                    "score_impact": -5

                })



  

    if ssl_info:


        ssl_status = ssl_info.get(
            "status"
        )



        if ssl_status == "Certificado vencido":


            score -= 20


            details.append({

                "severity": "ALTO",

                "title":
                "Certificado SSL vencido",

                "description":
                "El certificado digital del sitio expiró.",

                "impact":
                "Los usuarios pueden recibir advertencias de seguridad.",

                "recommendation":
                "Renovar el certificado SSL/TLS.",

                "score_impact": -20

            })



        elif ssl_status == "Certificado próximo a vencer":


            score -= 5


            details.append({

                "severity": "BAJO",

                "title":
                "Certificado SSL próximo a vencer",

                "description":
                "El certificado expirará próximamente.",

                "impact":
                "Puede provocar interrupciones si no se renueva.",

                "recommendation":
                "Renovar el certificado antes de la fecha de expiración.",

                "score_impact": -5

            })





    if status_code and status_code >= 500:


        details.append({

            "severity": "INFO",

            "title":
            "Servidor respondió con error HTTP",

            "description":
            "El servidor devolvió un código HTTP 5xx.",

            "impact":
            "Algunos resultados pueden contener falsos positivos.",

            "recommendation":
            "Realizar nuevamente el análisis cuando el servicio esté disponible.",

            "score_impact": 0

        })





    score = max(
        0,
        min(score, 100)
    )




    if status_code and status_code >= 500:

        level = "INCOMPLETE"

        title = "Análisis incompleto"

        description = (
            "El servidor no respondió correctamente "
            "por lo que algunos controles no pudieron evaluarse."
    )

    elif score >= 95:


        level = "GOOD"

        title = " Buena configuración de seguridad"

        description = (
            "La página analizada cuenta con configuraciones "
            "de seguridad recomendadas visibles desde Internet."
        )



    elif score >= 80:


        level = "IMPROVEMENT"

        title = " Configuración con mejoras recomendadas"

        description = (
            "Se detectaron configuraciones que pueden fortalecerse."
        )



    elif score >= 50:


        level = "WARNING"

        title = " Configuración con riesgos detectados"

        description = (
            "Existen varios puntos que requieren revisión."
        )



    else:


        level = "CRITICAL"

        title = " Configuración insegura"

        description = (
            "Se encontraron problemas importantes que deben corregirse."
        )



    return {

        "score": score,

        "level": level,

        "title": title,

        "description": description,

        "details": details

    }