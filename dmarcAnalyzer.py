"""
DMARC Analyzer
reads a bunch of xml DMARC Reports and exports the extracted data into a human readable csv format

Additionally needed packages: pandas, geoip
Install by: pip install pandas, geoip

Furthermore needed: andas, GeoLite2-ASN.mmdb and GeoLite2-City.mmdb
Can be obtained for example from https://dev.maxmind.com/geoip/geoip2/geolite2/ after free registration
"""

import os
import xml.etree.ElementTree as ET
import pandas as pd
import socket
import geoip2.database
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
        with geoip2.database.Reader(GEOIP_CITY_DB_PATH) as city_reader, \
             geoip2.database.Reader(GEOIP_ASN_DB_PATH) as asn_reader:
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
    email = report_info.find('email').text  # DMARC report source
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
        row = {
            'org_name': '"' + org_name + '"',  # Ensure string in CSV
            'email': '"' + email + '"',  # DMARC report source
            'report_id': '"' + report_id + '"',  # Ensure string in CSV
            'domain': domain,
            'begin': begin_date.strftime('%Y-%m-%d %H:%M:%S'),
            'end': end_date.strftime('%Y-%m-%d %H:%M:%S')
        }

        # Source IP
        source_ip = record.find('row/source_ip').text
        row['source_ip'] = '"' + source_ip + '"'  # Ensure string in CSV

        # Reverse DNS and GeoIP lookup
        row['reverse_dns'] = get_reverse_dns(source_ip)
        country, asn, asn_name = get_geoip_info(source_ip)
        row['country'] = country
        row['asn'] = '"' + str(asn) + '"'  # Ensure string in CSV
        row['asn_name'] = asn_name

        # Count and policy evaluated
        row['count'] = int(record.find('row/count').text)
        policy_evaluated = record.find('row/policy_evaluated')
        row['disposition'] = policy_evaluated.find('disposition').text
        row['dkim'] = policy_evaluated.find('dkim').text
        row['spf'] = policy_evaluated.find('spf').text

        records.append(row)

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

    return pd.DataFrame(all_records)

# Exportieren zu CSV
csv_file_path = os.path.join(DMARC_DIRECTORY, 'dmarc_summary_report.csv')
dmarc_data = process_dmarc_reports(DMARC_DIRECTORY)
dmarc_data.to_csv(csv_file_path, index=False, quoting=1)  # Use QUOTE_MINIMAL

print(f"The grouped DMARC report has been created: {csv_file_path}")
