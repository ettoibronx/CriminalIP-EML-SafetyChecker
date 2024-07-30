import email
import json
import os
import time
import re
import urllib.request
from email import policy
from email.parser import BytesParser
from ipaddress import ip_address, ip_network
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urlunparse


def extract_email_headers(msg):
    headers = {
        "From": msg["From"],
        "To": msg["To"],
        "Date": msg["Date"],
        "Subject": msg["Subject"],
        "Received": msg.get_all("Received"),
    }
    return headers


def extract_ip_addresses(received_headers):
    ip_addresses = []
    if received_headers:
        for header in received_headers:
            ip_matches = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", header)
            for ip in ip_matches:
                try:
                    ip_obj = ip_address(ip)
                    ip_addresses.append({"IP": str(ip_obj), "Header": header})
                except ValueError:
                    continue
    return ip_addresses


def is_valid_url(url):
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            return response.status == 200
    except:
        return False


def extract_urls_from_html(body):
    soup = BeautifulSoup(body, "html.parser")
    urls = [a["href"] for a in soup.find_all("a", href=True)]
    return [url for url in urls if is_valid_url(url)]


def extract_urls_from_text(body):
    url_regex = re.compile(
        r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"
    )
    return [url for url in url_regex.findall(body) if is_valid_url(url)]


def is_internal_ip(ip):
    private_networks = [
        ip_network("10.0.0.0/8"),
        ip_network("172.16.0.0/12"),
        ip_network("192.168.0.0/16"),
        ip_network("127.0.0.0/8"),
        ip_network("::1/128"),
        ip_network("fc00::/7"),
        ip_network("fe80::/10"),
    ]
    ip_obj = ip_address(ip)
    return any(ip_obj in net for net in private_networks)


def parse_eml(file_path):
    with open(file_path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

        headers = extract_email_headers(msg)
        ip_addresses = extract_ip_addresses(headers.get("Received", []))

        body = ""
        urls = []
        if msg.is_multipart():
            for part in msg.iter_parts():
                if part.get_content_type() in ["text/plain", "text/html"]:
                    charset = part.get_content_charset() or "utf-8"
                    part_body = part.get_payload(decode=True).decode(
                        charset, errors="ignore"
                    )
                    body += part_body
                    if part.get_content_type() == "text/html":
                        urls.extend(extract_urls_from_html(part_body))
                    else:
                        urls.extend(extract_urls_from_text(part_body))
        else:
            if msg.get_content_type() in ["text/plain", "text/html"]:
                charset = msg.get_content_charset() or "utf-8"
                body = msg.get_payload(decode=True).decode(charset, errors="ignore")
                if msg.get_content_type() == "text/html":
                    urls = extract_urls_from_html(body)
                else:
                    urls = extract_urls_from_text(body)

        return {
            "From": headers["From"],
            "To": headers["To"],
            "Date": headers["Date"],
            "Subject": headers["Subject"],
            "IP Addresses": ip_addresses,
            "URLs": [{"URL": url} for url in urls],
        }


def print_parsed_data(parsed_data):
    print("\n========================[  EML Parsing Result ]========================\n")
    for key, value in parsed_data.items():
        if isinstance(value, list):
            print(f"{key}:")
            for item in value:
                print(f"  - {item}")
        else:
            print(f"{key}: {value}")


def is_response_successful(response):
    return response.status_code == 200


def cip_ip_malicious_info(ip, api_key):
    url = f"https://api.criminalip.io/v1/feature/ip/malicious-info?ip={ip}"
    headers = {"x-api-key": api_key}

    response = requests.get(url, headers=headers)
    if is_response_successful(response):
        try:
            result_data = response.json()
            if result_data.get("status") != 200:
                return None
            return result_data.get("is_malicious")
        except (json.JSONDecodeError, KeyError) as e:
            print(f"[ERROR] {e}")
            return None


def cip_domain_scan(scan_url, api_key):
    url = "https://api.criminalip.io/v1/domain/scan"
    payload = {"query": scan_url}
    headers = {"x-api-key": api_key}
    response = requests.request("POST", url, headers=headers, data=payload)
    if is_response_successful(response):
        try:
            result_data = response.json()
            if result_data.get("status") != 200:
                return result_data.get("status")
            return result_data.get("data", {}).get("scan_id")
        except (json.JSONDecodeError, KeyError) as e:
            print(f"[ERROR] {e}")
            return None


def cip_domain_status(scan_id, api_key):
    url = f"https://api.criminalip.io/v1/domain/status/{scan_id}"
    headers = {"x-api-key": api_key}

    response = requests.get(url, headers=headers)
    if is_response_successful(response):
        try:
            result_data = response.json()
            if result_data.get("status") != 200:
                return None
            return result_data.get("data", {}).get("scan_percentage")
        except (json.JSONDecodeError, KeyError) as e:
            print(f"[ERROR] {e}")
            return None


def cip_domain_report(scan_id, api_key):
    url = f"https://api.criminalip.io/v2/domain/report/{scan_id}"
    headers = {"x-api-key": api_key}

    response = requests.get(url, headers=headers)
    if is_response_successful(response):
        try:
            result_data = json.loads(response.text)
            if (
                result_data.get("status") != 200
                or result_data.get("data", {}).get("count") == 0
            ):
                return None, None, None, None

            domain_score = (
                result_data.get("data", {})
                .get("main_domain_info", {})
                .get("domain_score")
                .get("score")
            )

            domain_score_percentage = (
                result_data.get("data", {})
                .get("main_domain_info", {})
                .get("domain_score")
                .get("score_percentage")
            )

            fake_domain = result_data.get("data", {}).get("summary").get("fake_domain")

            mail_server = result_data.get("data", {}).get("summary").get("mail_server")

            return domain_score, domain_score_percentage, fake_domain, mail_server

        except (json.JSONDecodeError, KeyError) as e:
            print(f"[ERROR] {e}")
            return None, None, None, None


def is_valid_api_key(api_key):
    pattern = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d]{60}$")
    return bool(pattern.match(api_key))


def read_eml_file(file_path):
    with open(file_path, "rb") as f:
        msg = email.message_from_binary_file(f)
    return msg


def get_body_from_eml(msg):
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/html":
                payload = part.get_payload(decode=True)
                return payload.decode("utf-8", errors="ignore")
    else:
        payload = msg.get_payload(decode=True)
        return payload.decode("utf-8", errors="ignore")
    return ""


def extract_urls(text):
    soup = BeautifulSoup(text, "html.parser")
    urls = [a["href"].strip() for a in soup.find_all("a", href=True)]

    unique_urls = {}
    for url in urls:
        parsed_url = urlparse(url)
        main_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        unique_urls[main_url] = url

    return list(unique_urls.values())


def clean_url(url):
    cleaned_url = url.split(" ")[0]
    parsed_url = urlparse(cleaned_url)
    cleaned_path = (
        "/".join(parsed_url.path.split("/")[:-1]) + "/" + parsed_url.path.split("/")[-1]
    )
    return urlunparse((parsed_url.scheme, parsed_url.netloc, cleaned_path, "", "", ""))


def main(file_path, api_key):
    if not os.path.exists(file_path):
        print(f"File {file_path} does not exist.")
        return

    if not is_valid_api_key(api_key):
        print("Invalid API key format.")
        return

    parsed_data = parse_eml(file_path)
    print_parsed_data(parsed_data)

    print("\n========================[  Criminal IP Report ]========================\n")

    for ip_info in parsed_data["IP Addresses"]:
        ip = ip_info["IP"]
        if not is_internal_ip(ip):
            ip_result = cip_ip_malicious_info(ip, api_key)
            if ip_result is True:
                print(f"{ip} : Malicious")
            else:
                print(f"{ip} : Clean")

    msg = read_eml_file(file_path)
    body = get_body_from_eml(msg)
    if body:
        urls = extract_urls(body)
        cleaned_urls = [clean_url(url) for url in urls]

        for url in cleaned_urls:
            scan_id = cip_domain_scan(str(url), api_key)
            if scan_id == 420:
                print("Not Domain")
                return
            while cip_domain_status(scan_id, api_key) != 100:
                time.sleep(15)
            domain_score, domain_score_percentage, fake_domain, mail_server = (
                cip_domain_report(scan_id, api_key)
            )
            print(f"\nURL: {url}")
            print(f"- Domain Score: {domain_score}")
            print(f"- Domain Score Percentage: {domain_score_percentage}")
            print(f"- Fake Domain: {fake_domain}")
            print(f"- Mail Server: {mail_server}\n")
    else:
        print("No valid body content found.")


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python CriminalIP-EML-SafetyChecker.py <file_path>")
        sys.exit(1)

    file_path = sys.argv[1]
    api_key = "YOUR APIKEY"
    main(file_path, api_key)
    print("=======================================================================\n")
