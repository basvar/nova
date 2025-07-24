import socket
import sys
import ssl
import os
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from colorama import init, Fore
import threading
import time
from bs4 import BeautifulSoup
import configparser

instagram = '@soybasvar'
sitio_web = 'https://basvar.com'
github = 'https://github.com/basvar'

VERSION = '1.0.0'

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'  # white
Y = '\033[33m'  # yellow

banner = r'''
███╗   ██╗ ██████╗ ██╗   ██╗ █████╗ 
████╗  ██║██╔═══██╗██║   ██║██╔══██╗
██╔██╗ ██║██║   ██║██║   ██║███████║
██║╚██╗██║██║   ██║╚██╗ ██╔╝██╔══██║
██║ ╚████║╚██████╔╝ ╚████╔╝ ██║  ██║
╚═╝  ╚═══╝ ╚═════╝   ╚═══╝  ╚═╝  ╚═╝
Descubra la verdadera dirección IP de los sitios web protegidos por Cloudflare y otros.
'''

init()

def print_banners():
    """
    prints the program banners
    """
    print(f'{R}{banner}{W}\n')
    print(f'{G}[+] {Y}Version      : {W}{VERSION}')
    print(f'{G}[+] {Y}Creado por   : {W}Basvar')
    print(f'{G} \u2514\u27A4 {Y}Sitio web      : {W}{sitio_web}')
    print(f'{G} \u2514\u27A4 {Y}Instagram      : {W}{instagram}')
    print(f'{G} \u2514\u27A4 {Y}Github       : {W}{github}\n')

def is_using_cloudflare(domain):
    try:
        response = requests.head(f"https://{domain}", timeout=5)
        headers = response.headers
        if "server" in headers and "cloudflare" in headers["server"].lower():
            return True
        if "cf-ray" in headers:
            return True
        if "cloudflare" in headers:
            return True
    except (requests.exceptions.RequestException, requests.exceptions.ConnectionError):
        pass

    return False

def detect_web_server(domain):
    try:
        response = requests.head(f"http://{domain}", timeout=5)
        server_header = response.headers.get("Server")
        if server_header:
            return server_header.strip()
    except (requests.exceptions.RequestException, requests.exceptions.ConnectionError):
        pass

    return "UNKNOWN"

def get_ssl_certificate_info(host):
    try:
        context = ssl.create_default_context()
        with context.wrap_socket(socket.socket(), server_hostname=host) as sock:
            sock.connect((host, 443))
            certificate_der = sock.getpeercert(True)

        certificate = x509.load_der_x509_certificate(certificate_der, default_backend())

        # Extract relevant information from the certificate
        common_name = certificate.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        issuer = certificate.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        validity_start = certificate.not_valid_before
        validity_end = certificate.not_valid_after

        return {
            "Common Name": common_name,
            "Issuer": issuer,
            "Validity Start": validity_start,
            "Validity End": validity_end,
        }
    except Exception as e:
        print(f"{Fore.RED}Error al extraer la información del certificado SSL: {e}{Fore.RESET}")
        return None

def find_subdomains_with_ssl_analysis(domain, filename, timeout=20):
    #if not is_using_cloudflare(domain):
        #print(f"{C}Website is not using Cloudflare. Subdomain scan is not needed.{W}")
        #return

    subdomains_found = []
    subdomains_lock = threading.Lock()

    # subdomain scanning...

    def check_subdomain(subdomain):
        subdomain_url = f"https://{subdomain}.{domain}"

        try:
            response = requests.get(subdomain_url, timeout=timeout)
            if response.status_code == 200:
                with subdomains_lock:
                    subdomains_found.append(subdomain_url)
                    print(f"{Fore.GREEN}Subdominio \u2514\u27A4: {subdomain_url}{Fore.RESET}")
        except requests.exceptions.RequestException as e:
            if "Max retries exceeded with url" in str(e):
                pass

    with open(filename, "r") as file:
        subdomains = [line.strip() for line in file.readlines()]

    print(f"\n{Fore.YELLOW}Iniciando escaneo...")
    start_time = time.time()

    threads = []
    for subdomain in subdomains:
        thread = threading.Thread(target=check_subdomain, args=(subdomain,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    end_time = time.time()
    elapsed_time = end_time - start_time
    print(f"\n{G} \u2514\u27A4 {C}Total Subdominios escaneados:{W} {len(subdomains)}")
    print(f"{G} \u2514\u27A4 {C}Encontrados:{W} {len(subdomains_found)}")
    print(f"{G} \u2514\u27A4 {C}Tiempo:{W} {elapsed_time:.2f} segundos")

    real_ips = []

    for subdomain in subdomains_found:
        subdomain_parts = subdomain.split('//')
        if len(subdomain_parts) > 1:
            host = subdomain_parts[1]
            real_ip = get_real_ip(host)
            if real_ip:
                real_ips.append((host, real_ip))
                print(f"\n{Fore.YELLOW}[+] {Fore.CYAN}IP real para {Fore.GREEN}{host}:{Fore.RED} {real_ip}")

                # Perform SSL Certificate Analysis
                ssl_info = get_ssl_certificate_info(host)
                if ssl_info:
                    print(f"{Fore.RED}   [+] {Fore.CYAN}SSL:")
                    for key, value in ssl_info.items():
                        print(f"{Fore.RED}      \u2514\u27A4 {Fore.CYAN}{key}:{W} {value}")

    if not real_ips:
        print(f"{R}No se encontraron direcciones IP reales para los subdominios.")
    else:
        print("\nCompletado!!\n")
        # for link in subdomains_found:
        # print(link)

def get_real_ip(host):
    try:
        real_ip = socket.gethostbyname(host)
        return real_ip
    except socket.gaierror:
        return None




def get_domain_historical_ip_address(domain):
    try:
        url = f"https://viewdns.info/iphistory/?domain={domain}"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.102 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
    
        }
        response = requests.get(url, headers=headers)
        html = response.text
        soup = BeautifulSoup(html, 'html.parser')
        table = soup.find('table', {'border': '1'})

        if table:
            rows = table.find_all('tr')[2:]
            print(f"\n{Fore.GREEN}[+] {Fore.YELLOW}Historical IP Address Info from {C}Viewdns{Y} for {Fore.GREEN}{domain}:{W}")
            for row in rows:
                columns = row.find_all('td')
                ip_address = columns[0].text.strip()
                location = columns[1].text.strip()
                owner = columns[2].text.strip()
                last_seen = columns[3].text.strip()
                print(f"\n{R} [+] {C}IP Address: {R}{ip_address}{W}")
                print(f"{Y}  \u2514\u27A4 {C}Location: {G}{location}{W}")
                print(f"{Y}  \u2514\u27A4 {C}Owner: {G}{owner}{W}")
                print(f"{Y}  \u2514\u27A4 {C}Last Seen: {G}{last_seen}{W}")
        else:
            None
    except:
        None


if __name__ == "__main__":
    if len(sys.argv) >= 2:
        domain = sys.argv[1]
    else:
        domain = input(f"{Y}[?]{W} Ingresa el dominio: ").strip()

    if not domain:
        print(f"{R}[ERROR]{W} No ingresaste ningún dominio. Saliendo...")
        sys.exit(1)

    filename = "bv.txt"
    print_banners()
    CloudFlare_IP = get_real_ip(domain)

    print(f"\n{Fore.GREEN}[!] {C}Comprobando si el sitio web utiliza Cloudflare{Fore.RESET}\n")

    if is_using_cloudflare(domain):
        print(f"\n{R}Sitio web: {W}{domain}")
        print(f"{R}Dirección IP: {W}{CloudFlare_IP}\n")
        get_domain_historical_ip_address(domain)

        print(f"\n{Fore.GREEN}[+] {Fore.YELLOW}Escaneo de subdominios.{Fore.RESET}")
        find_subdomains_with_ssl_analysis(domain, filename)
    else:
        print(f"{Fore.RED}- El sitio web no utiliza Cloudflare. (inseguro)")
        technology = detect_web_server(domain)
        print(f"\n{Fore.GREEN}[+] {C}El sitio web está utilizando: {Fore.GREEN} {technology}")
        proceed = input(f"\n{Fore.YELLOW}> ¿Quieres continuar? {Fore.GREEN}(si/no): ").lower()

        if proceed == "si":
            print(f"\n{R}Sitio web: {W}{domain}")
            print(f"{R}Dirección IP: {W}{CloudFlare_IP}\n")
            get_domain_historical_ip_address(domain)
            
            print(f"{Fore.GREEN}[+] {Fore.YELLOW}Escaneo de subdominios.{Fore.RESET}")
            find_subdomains_with_ssl_analysis(domain, filename)
        else:
            print(f"{R}Operacion cancelada. Saliendo....{W}")

        input(f"\n{Y}[!] Presiona Enter para salir...{W}")
