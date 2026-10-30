
   
import socket
import ssl
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlparse

BANNER = """
  ____  _ _       ____                     _
 / ___|(_) |_ ___/ ___|_   _  __ _ _ __ __| |
 \___ \| | __/ _ \___ \ | | |/ _` | '__/ _` |
  ___) | | ||  __/___) | |_| | (_| | | | (_| |
 |____/|_|\__\___|____/ \__,_|\__,_|_|  \__,_|

       WEB SECURITY ANALYZER v1.0
"""

SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "Content Security Policy",
    "x-content-type-options": "X-Content-Type-Options",
    "x-frame-options": "X-Frame-Options",
    "referrer-policy": "Referrer Policy",
}


def get_url(domain):
    domain = domain.strip()

    if not domain:
        raise ValueError("Informe um domínio.")

    if "://" not in domain:
        domain = "https://" + domain

    parsed = urlparse(domain)

    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("Informe um endereço HTTPS válido.")

    if parsed.username or parsed.password:
        raise ValueError("Credenciais na URL não são permitidas.")

    return domain, parsed.hostname


def check_https(url):
    print("\n[1] HTTPS")

    try:
        request = urllib.request.Request(
            url,
            headers={"User-Agent": "SiteGuard/1.0"},
            method="GET"
        )

        with urllib.request.urlopen(request, timeout=10) as response:
            print("[+] HTTPS funcionando")
            print(f"[+] Status HTTP: {response.status}")
            print(f"[+] URL final: {response.url}")
            return response.headers

    except Exception as error:
        print(f"[-] Falha na conexão: {error}")
        return None


def check_tls(host):
    print("\n[2] CERTIFICADO TLS")

    try:
        context = ssl.create_default_context()

        with socket.create_connection((host, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as secure:
                cert = secure.getpeercert()

        expiration = datetime.strptime(
            cert["notAfter"],
            "%b %d %H:%M:%S %Y %Z"
        ).replace(tzinfo=timezone.utc)

        remaining = expiration - datetime.now(timezone.utc)

        print("[+] Certificado válido")
        print(f"[+] Expira em: {expiration}")
        print(f"[+] Dias restantes: {remaining.days}")

    except Exception as error:
        print(f"[-] Erro ao verificar TLS: {error}")


def check_headers(headers):
    print("\n[3] CABEÇALHOS DE SEGURANÇA")

    if headers is None:
        print("[-] Não foi possível obter os cabeçalhos.")
        return

    score = 0

    for header, name in SECURITY_HEADERS.items():
        if header in headers:
            print(f"[+] {name}: PRESENTE")
            score += 1
        else:
            print(f"[-] {name}: AUSENTE")

    print(f"\nResultado: {score}/{len(SECURITY_HEADERS)} cabeçalhos presentes")


def main():
    print(BANNER)

    domain = input("Digite o domínio para analisar: ")

    try:
        url, host = get_url(domain)
    except ValueError as error:
        print(f"[-] {error}")
        return

    print(f"\nAnalisando: {host}")
    print("Use apenas sites próprios ou com autorização.")

    headers = check_https(url)
    check_tls(host)
    check_headers(headers)

    print("\n[+] Análise finalizada.")
    print("SiteGuard v1.0")


if __name__ == "__main__":
    main()
 