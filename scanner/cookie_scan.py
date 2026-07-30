def analyze_cookies(headers):

    cookies = headers.get("Set-Cookie")

    if not cookies:
        return [
            {
                "status": "INFO",
                "message": "No se encontraron cookies."
            }
        ]

    results = []

    security_attributes = {
        "Secure": "Cookie sin atributo Secure.",
        "HttpOnly": "Cookie sin atributo HttpOnly.",
        "SameSite": "Cookie sin atributo SameSite."
    }

    cookie_data = cookies.lower()

    for attribute, message in security_attributes.items():

        if attribute.lower() in cookie_data:

            results.append({
                "status": "OK",
                "message": f"Atributo {attribute} configurado."
            })

        else:

            results.append({
                "status": "WARNING",
                "message": message
            })


    return results