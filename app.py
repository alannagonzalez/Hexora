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
                f"[{result['severity']}] "
                f"{result['message']}"
            )

        else:

            print(
                f"{result.get('status', 'INFO')} - "
                f"{result.get('message', '')}"
            )


def run_scan(url):

    dns_info = get_domain_ip(url)

    if "error" in dns_info:
        return {"error": dns_info["error"]}

    headers_info = scan_headers(url)

    if "error" in headers_info:
        return {"error": headers_info["error"]}

    headers = headers_info["headers"]

    security_results = check_security_headers(headers)

    vulnerabilities = analyze_vulnerabilities(headers)

    cookie_results = analyze_cookies(headers)

    method_results = check_http_methods(url)

    technologies = detect_technologies(headers)

    ssl_info = get_ssl_info(dns_info["domain"])

    port_results = scan_ports(dns_info["domain"])

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

    print_section("Información del dominio")

    print(f"Dominio: {results['domain']['domain']}")
    print(f"IP: {results['domain']['ip']}")

    print_section("Información HTTP")

    print(
        f"Código de estado: "
        f"{results['http']['status_code']}"
    )

    if results["http"]["status_code"] >= 500:

        print(
            "ADVERTENCIA: El servidor devolvió un error HTTP. "
            "Los resultados pueden contener falsos positivos."
        )

    print(
        f"URL final: "
        f"{results['http']['final_url']}"
    )

    print("\nHeaders encontrados:")

    for header, value in results["http"]["headers"].items():

        print(f"{header}: {value}")

    print_section("Análisis de seguridad HTTP")

    display_results(results["security"])

    print_section("Configuraciones inseguras")

    if results["vulnerabilities"]:

        display_results(results["vulnerabilities"])

    else:

        print("No se encontraron configuraciones inseguras.")

    print_section("Análisis de Cookies")

    display_results(results["cookies"])

    print_section("Métodos HTTP")

    display_results(results["methods"])

    print_section("Tecnologías detectadas")

    for technology in results["technologies"]:

        print(
            f"{technology['technology']}: "
            f"{technology['value']}"
        )

    print_section("Análisis SSL")

    ssl = results["ssl"]

    if "error" in ssl:

        print(ssl["error"])

    else:

        print(f"Estado: {ssl['status']}")
        print(f"Expira: {ssl['expires']}")
        print(f"Emisor: {ssl['issuer']}")

    print_section("Escaneo de puertos")

    for port in results["ports"]:

        print(
            f"Puerto {port['port']} "
            f"({port['service']}): "
            f"{port['status']} | "
            f"Tiempo: {port['response_time']}"
        )

    print_section("Evaluación de riesgo")

    print(f"Puntuación: {results['risk']['score']}")
    print(f"Nivel de riesgo: {results['risk']['level']}")

    if results["risk"]["details"]:

        print("\nHallazgos:")

        for finding in results["risk"]["details"]:

            print(
                f"[{finding['severity']}] "
                f"{finding['message']}"
            )


def main():

    url = input(
        "Ingrese la URL que desea escanear: "
    ).strip()

    if not validate_url(url):

        print("URL inválida.")
        return

    results = run_scan(url)

    print_report(results)


if __name__ == "__main__":

    main()