def detect_technologies(headers):

    technologies = []


    server = headers.get(
        "Server",
        ""
    )


    powered_by = headers.get(
        "X-Powered-By",
        ""
    )


    via = headers.get(
        "Via",
        ""
    )


    if server:

        technologies.append({
            "technology": "Servidor Web",
            "value": server
        })


        server_lower = server.lower()


        if "apache" in server_lower:

            technologies.append({
                "technology": "Servidor detectado",
                "value": "Apache"
            })


        elif "nginx" in server_lower:

            technologies.append({
                "technology": "Servidor detectado",
                "value": "Nginx"
            })


        elif "iis" in server_lower:

            technologies.append({
                "technology": "Servidor detectado",
                "value": "Microsoft IIS"
            })



    if powered_by:

        technologies.append({
            "technology": "Framework / Plataforma",
            "value": powered_by
        })


        powered_lower = powered_by.lower()


        if "php" in powered_lower:

            technologies.append({
                "technology": "Lenguaje",
                "value": "PHP"
            })


        elif "asp.net" in powered_lower:

            technologies.append({
                "technology": "Framework",
                "value": "ASP.NET"
            })



    if "cf-ray" in headers:

        technologies.append({
            "technology": "CDN / Proxy",
            "value": "Cloudflare"
        })



    if via:

        technologies.append({
            "technology": "Proxy / Gateway",
            "value": via
        })



    if "X-AspNet-Version" in headers:

        technologies.append({
            "technology": "Framework",
            "value": "ASP.NET"
        })



    if "X-Generator" in headers:

        technologies.append({
            "technology": "CMS / Generador",
            "value": headers["X-Generator"]
        })



    if not technologies:

        technologies.append({
            "technology": "Desconocido",
            "value": "No se pudo identificar tecnología."
        })


    return technologies