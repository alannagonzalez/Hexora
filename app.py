from utils.validator import validate_url
from scanner.dns_scan import get_domain_ip
from scanner.headers import scan_headers
from scanner.security_checks import check_security_headers
from scanner.ssl_scan import get_ssl_info
from scanner.port_scan import scan_ports
from scanner.vulnerability_scan import analyze_vulnerabilities
from scanner.cookie_scan import analyze_cookies
from scanner.http_methods import check_http_methods
from scanner.technology_scan import detect_technologies
from scanner.risk_analysis import calculate_risk



def print_section(title):

    print("\n" + "=" * 40)
    print(title)
    print("=" * 40)



def display_results(results):

    if not results:

        print("No se encontraron resultados.")

        return


    for result in results:


        if "check" in result:

            print(
                f"{result['status']} - "
                f"{result['check']}: "
                f"{result['message']}"
            )


        elif "severity" in result:

            print(
                f"\n[{result['severity']}] "
                f"{result.get('title', result.get('message'))}"
            )


            if "description" in result:

                print(
                    f"Descripción: {result['description']}"
                )


            if "impact" in result:

                print(
                    f"Impacto: {result['impact']}"
                )


            if "recommendation" in result:

                print(
                    f"Recomendación: {result['recommendation']}"
                )


        else:

            print(
                f"{result.get('status','INFO')} - "
                f"{result.get('message','')}"
            )



def run_scan(url):


    dns_info = get_domain_ip(url)


    if "error" in dns_info:

        return {
            "error": dns_info["error"]
        }



    headers_info = scan_headers(url)


    if "error" in headers_info:

        return {
            "error": headers_info["error"]
        }



    if headers_info["status_code"] >= 500:

        return {
            "error":
            "El servidor respondió con un error HTTP 5xx. "
            "El análisis no es confiable en este momento."
        }



    headers = headers_info["headers"]



    security_results = check_security_headers(
        headers
    )


    vulnerabilities = analyze_vulnerabilities(
        headers
    )


    cookie_results = analyze_cookies(
        headers
    )


    method_results = check_http_methods(
        url
    )


    technologies = detect_technologies(
        headers
    )


    ssl_info = get_ssl_info(
        dns_info["domain"]
    )


    port_results = scan_ports(
        dns_info["domain"]
    )


    if isinstance(port_results, dict):

        port_results = []



    risk = calculate_risk(
        vulnerabilities,
        port_results,
        ssl_info,
        headers_info["status_code"]
    )



    return {


        "domain": dns_info,


        "http": {

            "status_code": headers_info["status_code"],

            "final_url": headers_info["final_url"],

            "headers": dict(headers)

        },


        "security": security_results,


        "vulnerabilities": vulnerabilities,


        "cookies": cookie_results,


        "methods": method_results,


        "technologies": technologies,


        "ssl": ssl_info,


        "ports": port_results,


        "risk": risk

    }




def print_report(results):


    if "error" in results:

        print(results["error"])

        return



    print_section(
        "Información del dominio"
    )


    print(
        f"Dominio: {results['domain']['domain']}"
    )


    print(
        f"IP: {results['domain']['ip']}"
    )



    print_section(
        "Información HTTP"
    )


    status_code = results["http"]["status_code"]


    print(
        f"Código de estado: {status_code}"
    )



    if status_code >= 500:


        print(
            "\n⚠️ ADVERTENCIA:"
        )


        print(
            "El servidor devolvió un error HTTP 5xx."
        )


        print(
            "Los resultados pueden contener falsos positivos "
            "porque el servicio no respondió correctamente."
        )



    print(
        f"URL final: {results['http']['final_url']}"
    )



    print("\nHeaders encontrados:")


    for header, value in results["http"]["headers"].items():

        print(
            f"{header}: {value}"
        )



    print_section(
        "Análisis de seguridad HTTP"
    )


    display_results(
        results["security"]
    )



    print_section(
        "Configuraciones inseguras"
    )


    display_results(
        results["vulnerabilities"]
    )



    print_section(
        "Análisis de Cookies"
    )


    display_results(
        results["cookies"]
    )



    print_section(
        "Métodos HTTP"
    )


    display_results(
        results["methods"]
    )



    print_section(
        "Tecnologías detectadas"
    )


    for technology in results["technologies"]:


        print(
            f"{technology['technology']}: "
            f"{technology['value']}"
        )



    print_section(
        "Análisis SSL"
    )


    ssl = results["ssl"]


    if "error" in ssl:

        print(
            ssl["error"]
        )


    else:


        print(
            f"Estado: {ssl['status']}"
        )


        print(
            f"Expira: {ssl['expires']}"
        )


        print(
            f"Emisor: {ssl['issuer']}"
        )



    print_section(
        "Escaneo de puertos"
    )



    for port in results["ports"]:


        print(

            f"Puerto {port['port']} "
            f"({port['service']}): "
            f"{port['status']} | "
            f"Tiempo: {port.get('response_time','N/A')}"

        )



    print_section(
        "Resultado del análisis"
    )



    risk = results["risk"]

    score = risk["score"]



    if score >= 90:


        title = "🟢 Buena configuración de seguridad"


        description = (
            "La página analizada cuenta con configuraciones "
            "de seguridad recomendadas visibles desde Internet."
        )



    elif score >= 75:


        title = "🟡 Configuración con mejoras recomendadas"


        description = (
            "Se detectaron configuraciones que pueden "
            "fortalecerse para mejorar la seguridad."
        )



    elif score >= 50:


        title = "🟠 Configuración con riesgos detectados"


        description = (
            "Existen varios puntos de seguridad que "
            "requieren revisión."
        )



    else:


        title = "🔴 Configuración insegura"


        description = (
            "Se encontraron problemas importantes "
            "que deben corregirse."
        )



    print(title)


    print(description)



    print(
        f"\nPuntuación: {score}/100"
    )



    print(
"""
Nota:
La puntuación representa únicamente el nivel de
cumplimiento de configuraciones de seguridad evaluadas
por Hexora.

Un resultado alto indica buenas prácticas detectadas,
pero no garantiza que la aplicación esté libre de
vulnerabilidades.
"""
)



    print(
"""
📋 Alcance del análisis

Hexora realiza un análisis externo de seguridad
sobre elementos visibles desde Internet.

Controles evaluados:

✓ Headers HTTP de seguridad
✓ Certificado SSL/TLS
✓ Configuración de cookies
✓ Métodos HTTP habilitados
✓ Puertos accesibles
✓ Tecnologías detectadas
✓ Configuraciones inseguras conocidas
"""
)



    print(
"""
⚠️ Limitaciones del análisis

Hexora evalúa configuraciones de seguridad visibles
desde Internet.

El análisis NO incluye:

- Revisión de código fuente.
- Análisis interno de bases de datos.
- Explotación de vulnerabilidades.
- Pruebas de lógica de negocio.
- Detección completa de SQL Injection o XSS avanzados.
"""
)



    print_section(
        "Hallazgos"
    )



    for finding in risk["details"]:


        print(
            f"\n[{finding['severity']}] "
            f"{finding.get('title', finding.get('message'))}"
        )


        if "description" in finding:

            print(
                f"Descripción: {finding['description']}"
            )


        if "impact" in finding:

            print(
                f"Impacto: {finding['impact']}"
            )


        if "recommendation" in finding:

            print(
                f"Recomendación: {finding['recommendation']}"
            )




def main():


    url = input(
        "Ingrese la URL que desea escanear: "
    ).strip()



    if not validate_url(url):

        print(
            "URL inválida."
        )

        return



    results = run_scan(url)


    print_report(results)




if __name__ == "__main__":

    main()