# IPTracker0x

IPTracker0x is an IP analysis tool that uses the [ipinfo.io](https://ipinfo.io) API to retrieve information about IPs, including their ASN and whether they belong to a list of malicious ASNs. It also generates reports in CSV and HTML formats with the results.

IPTracker0x utilizes the [ipinfo.io](https://ipinfo.io) API, which in its free version allows analyzing up to 50,000 IPs per month. This makes it ideal for handling large volumes of data in security incident investigations.

<p align="center">
<img src=https://imgur.com/6n0x5vI.png">
</p>

## Features

- Retrieves information for multiple IPs in parallel.
- Identifies IPs associated with malicious ASNs.
- Generates reports in CSV and HTML formats.
- Highlights IPs with malicious ASNs in the HTML report.
- Provides statistics on the most frequent countries in the analysis.

## Requirements

Before running the script, make sure you have the following dependencies installed:

```sh
pip install requests tqdm colorama pycountry
```

## Configuration

### API Key

The script uses the ipinfo.io API to retrieve IP information. You must have a valid API key and replace the `api_token` variable in the script with your own key:

```python
api_token = "YOUR_API_KEY"
```

### Adjusting the Number of Threads

To speed up IP queries, the script uses parallel processing. You can adjust the number of concurrent threads by modifying the `max_workers` parameter in the following line:

```python
with ThreadPoolExecutor(max_workers=10) as executor:
```

Adjust this value according to your system's capacity and the number of IPs to be processed.

## Usage

1. Add the IP addresses you want to analyze in a file named `ips.txt`, one per line.
2. Run the script with the following command:

```sh
python IPTracker0x.py
```

3. Upon completion, the results will be saved in `results_IPTracker0x.csv` and `report_IPTracker0x.html`.
4. Open `report_IPTracker0x.html` in a browser to view the report with highlighted data.

## Output Format

### CSV (`results_IPTracker0x.csv`)

The CSV file contains the following columns:

- `ip`: Analyzed IP address
- `hostname`: Associated hostname (if available)
- `city`: City of the IP
- `region`: Region of the IP
- `country`: Country of the IP
- `loc`: Coordinates of the IP
- `org`: Organization that owns the IP
- `asn`: Autonomous System Number (ASN)
- `bad_asn`: Indicates whether the IP belongs to a malicious ASN (`Yes` or `No`)

This format is ideal for those who want to work with queries or tables, making analysis easier using tools like Excel or databases.

### HTML (`report_IPTracker0x.html`)

- Contains a table with detailed information about each analyzed IP.
- IPs with malicious ASNs are highlighted in red.
- Displays a summary of the total IPs analyzed and the percentage of malicious ASNs.
- Includes a ranking of the top 10 most frequent countries in the analysis.

<p align="center">
<img src=https://imgur.com/kGKWyQg.png">
<img src=https://imgur.com/NsVhjks.png">
</p>

## Credits


Special thanks to [brianhama](https://github.com/brianhama/bad-asn-list) for his repository **bad-asn-list**, used to identify malicious ASNs.

## License

This project is open source and distributed under the MIT license.

