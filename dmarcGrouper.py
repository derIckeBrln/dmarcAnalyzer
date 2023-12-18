"""
DMARC Grouper
reads a bunch of xml DMARC Reports and exports the extracted data into a human readable csv format
additionally to the Analyzer it merges the data and groups it to asns

Additionally needed packages: pandas, geoip
Install by: pip install pandas, geoip

Furthermore needed: andas, GeoLite2-ASN.mmdb and GeoLite2-City.mmdb
Can be obtained for example from https://dev.maxmind.com/geoip/geoip2/geolite2/ after free registration 
"""

import os
import xml.etree.ElementTree as ET
import pandas as pd
import socket
from geoip2 import database
import datetime

# Set paths
GEOIP_CITY_DB_PATH = 'geoIp/GeoLite2-City.mmdb'
GEOIP_ASN_DB_PATH = 'geoIp/GeoLite2-ASN.mmdb'
DMARC_DIRECTORY = '.'

def get_geoip_info(ip):
    """
    Returns the country, ASN, and ASN name for an IP address using the GeoIP database.
    """
    try:
        with database.Reader(GEOIP_CITY_DB_PATH) as city_reader, \
             database.Reader(GEOIP_ASN_DB_PATH) as asn_reader:
            country = city_reader.city(ip).country.name
            asn_data = asn_reader.asn(ip)
            asn = asn_data.autonomous_system_number
            asn_name = asn_data.autonomous_system_organization
            return country, asn, asn_name
    except Exception as e:
        return None, None, None

def get_reverse_dns(ip):
    """
    Performs a reverse DNS lookup for an IP address and returns the hostname.
    """
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception as e:
        return None

def parse_dmarc_report(xml_file):
    """
    Parses a DMARC XML report and extracts relevant information.
    """
    tree = ET.parse(xml_file)
    root = tree.getroot()

    # Extracting report metadata
    report_info = root.find('report_metadata')
    org_name = report_info.find('org_name').text
    report_id = report_info.find('report_id').text
    date_range = report_info.find('date_range')

    # Extracting policy published
    policy_published = root.find('policy_published')
    domain = policy_published.find('domain').text

    # Convert Unix timestamps to datetime
    begin_date = datetime.datetime.utcfromtimestamp(int(date_range.find('begin').text))
    end_date = datetime.datetime.utcfromtimestamp(int(date_range.find('end').text))

    # Iterate over record elements and extract relevant data
    records = []
    for record in root.iter('record'):
        source_ip = record.find('row/source_ip').text
        reverse_dns = get_reverse_dns(source_ip)
        country, asn, asn_name = get_geoip_info(source_ip)
        count = int(record.find('row/count').text)
        policy_evaluated = record.find('row/policy_evaluated')
        disposition = policy_evaluated.find('disposition').text
        dkim = policy_evaluated.find('dkim').text
        spf = policy_evaluated.find('spf').text

        records.append({
            'org_name': org_name,
            'report_id': report_id,
            'domain': domain,
            'begin': begin_date,
            'end': end_date,
            'count': count,
            'source_ip': source_ip,
            'reverse_dns': reverse_dns,
            'country': country,
            'asn': asn,
            'asn_name': asn_name,
            'disposition': disposition,
            'dkim': dkim,
            'spf': spf
        })

    return records

def process_dmarc_reports(directory):
    """
    Processes all DMARC reports in the given directory and returns a grouped DataFrame.
    """
    all_records = []
    files = [f for f in os.listdir(directory) if f.endswith(".xml")]
    for i, file in enumerate(files):
        file_path = os.path.join(directory, file)
        records = parse_dmarc_report(file_path)
        all_records.extend(records)
        print(f"Processed: {file} ({i + 1}/{len(files)})")  # Processstate

    df = pd.DataFrame(all_records)

    # Group data
    grouped = df.groupby(
        ['domain', 'country', 'asn', 'asn_name', 'disposition', 'dkim', 'spf']
    ).agg({
        'begin': 'min',
        'end': 'max',
        'count': 'sum',
        'source_ip': lambda ips: "\n".join(set(ips)),
        'reverse_dns': lambda names: "\n".join(filter(None, set(names))),  # Filter out None values
    }).reset_index()

    # Adjust the 'source' column to include the hostname in parentheses only if it exists
    grouped['source'] = grouped.apply(
        lambda row: "\n".join(
            f'"{ip} ({dns})"' if dns else f'"{ip}"' for ip, dns in zip(row['source_ip'].split("\n"), row['reverse_dns'].split("\n"))
        ),
        axis=1
    )

    # Combine 'asn' and 'asn_name' into one column
    grouped['asn_info'] = grouped.apply(
        lambda row: f'{row["asn_name"]} ({row["asn"]})' if row["asn_name"] else f'({row["asn"]})',
        axis=1
    )

    # Reorder the columns
    grouped = grouped[['domain', 'begin', 'end', 'country', 'asn_info', 'count', 'disposition', 'dkim', 'spf', 'source']]

    return grouped

# Process and export to CSV
grouped_data = process_dmarc_reports(DMARC_DIRECTORY)
csv_file_path = os.path.join(DMARC_DIRECTORY, 'grouped_dmarc_summary_report.csv')
# Use quoting=1 to ensure numeric-like strings are quoted
grouped_data.to_csv(csv_file_path, index=False, quoting=1)

print(f"The grouped DMARC report has been created: {csv_file_path}")

