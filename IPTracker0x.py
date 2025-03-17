import csv
import requests
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import re
from colorama import init, Fore, Style
import pycountry

# Initialize colorama to work on Windows
init(autoreset=True)

# Input file containing the IPs
input_file = "ips.txt"

# API token for ipinfo.io (Replace with your own token)      ------- important! -------
api_token = "YOUR_API_KEY"

# URL of the bad ASN list CSV
bad_asn_url = "https://raw.githubusercontent.com/brianhama/bad-asn-list/refs/heads/master/bad-asn-list.csv"


# Application logo
def print_logo():
    logo = r"""

██╗██████╗ ████████╗██████╗  █████╗  ██████╗██╗  ██╗███████╗██████╗  ██████╗ ██╗  ██╗
██║██╔══██╗╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗██╔═████╗╚██╗██╔╝
██║██████╔╝   ██║   ██████╔╝███████║██║     █████╔╝ █████╗  ██████╔╝██║██╔██║ ╚███╔╝ 
██║██╔═══╝    ██║   ██╔══██╗██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗████╔╝██║ ██╔██╗ 
██║██║        ██║   ██║  ██║██║  ██║╚██████╗██║  ██╗███████╗██║  ██║╚██████╔╝██╔╝ ██╗
╚═╝╚═╝        ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝                                                            
    by corvus0x
    """
    print(Fore.CYAN + logo + Style.RESET_ALL)



def read_ips(file_path):
    with open(file_path, "r") as file:
        return [line.strip() for line in file if line.strip()]

def download_bad_asns(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            bad_asns = set()
            csv_reader = csv.reader(response.text.splitlines())
            next(csv_reader)
            for row in csv_reader:
                if row:
                    bad_asns.add(row[0])
            return bad_asns
        else:
            print(f"Error downloading bad ASN list: {response.status_code}")
            return set()
    except requests.exceptions.RequestException as e:
        print(f"Error downloading bad ASN list: {e}")
        return set()

def get_ip_info(ip, token, bad_asns):
    url = f"https://ipinfo.io/{ip}?token={token}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            org = data.get("org", "")
            asn_match = re.search(r"AS(\d+)", org)
            asn = asn_match.group(1) if asn_match else ""
            bad_asn = "Yes" if asn in bad_asns else "No"
            country_code = data.get("country", "")
            country_name = pycountry.countries.get(alpha_2=country_code).name if country_code else ""
            return {"ip": data.get("ip", ip), "hostname": data.get("hostname", ""), "city": data.get("city", ""), "region": data.get("region", ""), "country": country_name, "loc": data.get("loc", ""), "org": org, "asn": asn, "bad_asn": bad_asn}
        else:
            return {"ip": ip, "hostname": "", "city": "", "region": "", "country": "", "loc": "", "org": "", "asn": "", "bad_asn": "No"}
    except requests.exceptions.RequestException:
        return {"ip": ip, "hostname": "", "city": "", "region": "", "country": "", "loc": "", "org": "", "asn": "", "bad_asn": "No"}

def save_to_csv(data, file_path):
    with open(file_path, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=["ip", "hostname", "city", "region", "country", "loc", "org", "asn", "bad_asn"])
        writer.writeheader()
        writer.writerows(data)

def generate_html_report(data, output_file):
    total_ips = len(data)
    bad_asn_count = sum(1 for row in data if row["bad_asn"] == "Yes")
    bad_asn_percentage = (bad_asn_count / total_ips * 100) if total_ips > 0 else 0
    country_counts = Counter(row["country"] for row in data if row["country"])
    top_countries = country_counts.most_common(10)
    unique_countries = len(country_counts)
    unique_asns = len(set(row["asn"] for row in data if row["asn"]))
    
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>IPTracker0x Report</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background-color: #f4f4f9; color: #333; }}
            h1 {{
                color: #444;
                text-align: center;
                margin-top: 20px;
                font-size: 48px;
                font-weight: 900;
            }}
            h1::after {{
                content: '';
                display: block;
                width: 50px;
                margin: 10px auto;
                border-bottom: 3px solid #444;
            }}
            h2 {{ color: #333; margin-top: 30px; font-size: 24px; padding: 10px; }}
            .info-section {{
                width: 90%;
                margin: 30px auto;
                padding: 20px;
                border-radius: 8px;
                box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
                background-color: #f8f9fa;
                border-left: 5px solid #007bff;
            }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1); }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: center; }} 
            th {{ background-color: rgba(30, 144, 255, 0.8); color: #000; font-size: 18px; }}
            td {{ font-size: 16px; color: #444; }}
            .bad-asn {{ background-color:rgba(255, 165, 0, 0.3); }} 
        </style>
    </head>
    <body>
        <h1>IPTracker0x Report</h1>

        <div class="info-section">
            <h2>General Information</h2>
            <p><strong>Total IPs Processed:</strong> {total_ips}</p>
            <p><strong>Unique Countries:</strong> {unique_countries}</p>
            <p><strong>Unique ASNs:</strong> {unique_asns}</p>
            <p><strong>IPs with Noteworthy ASN:</strong> {bad_asn_count} ({bad_asn_percentage:.2f}%)</p>
        </div>

        <h2>Top 10 Most Frequent Countries</h2>
        <table>
            <tr><th>Country</th><th>Occurrences</th></tr>
            {''.join(f'<tr><td>{country}</td><td>{count}</td></tr>' for country, count in top_countries)}
        </table>

        <h2>IP Details</h2>
        <p>Note: IPs belonging to ASNs from cloud providers, managed hosting, and colocation facilities are marked in orange.</p>
        <table>
            <tr><th>IP</th><th>Hostname</th><th>City</th><th>Region</th><th>Country</th><th>ASN</th><th>Bad ASN</th></tr>
            {''.join(f'<tr class="{"bad-asn" if row["bad_asn"] == "Yes" else ""}"><td>{row["ip"]}</td><td>{row["hostname"]}</td><td>{row["city"]}</td><td>{row["region"]}</td><td>{row["country"]}</td><td>{row["asn"]}</td><td>{row["bad_asn"]}</td></tr>' for row in data)}
        </table>
    </body>
    </html>
    """
    with open(output_file, "w", encoding="utf-8") as file:
        file.write(html_content)

def main():
    print_logo()
    ips = read_ips(input_file)
    bad_asns = download_bad_asns(bad_asn_url)
    results = []

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(get_ip_info, ip, api_token, bad_asns): ip for ip in ips}
        with tqdm(total=len(ips), desc="Fetching IPs", unit="IP", colour="green") as progress:
            for future in as_completed(futures):
                results.append(future.result())
                progress.update(1)

    save_to_csv(results, "results_IPTracker0x.csv")
    generate_html_report(results, "report_IPTracker0x.html")
    
    # Display message in console with colors
    print(Fore.CYAN + f"Total IPs Analyzed: {len(ips)}")
    print()
    print(Fore.GREEN + Style.BRIGHT + "[INFO] Results saved in results_IPTracker0x.csv and report_IPTracker0x.html")

if __name__ == "__main__":
    main()