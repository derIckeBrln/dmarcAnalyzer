# dmarcAnalyzer
Analysis of DMARC Reports

This tools takes received DMARC reports and analyze them all together in order to have a report showing up which countries, asn and servers try to send emails that belong to your domain.

## Requirements
* Python
* Python packages: pandas, geoip
* GeoLite2-Database

## Installation
* get this repo
* install python
* install packages:
	* pip install pandas, geoip
* Get GeoIP-Database
	* Register for free on maxmind.com
	* Download databases from: https://dev.maxmind.com/geoip/geoip2/geolite2/
		* Needed: GeoLite2-ASN, GeoLite2-City
* Modify paths to DMARC-Files and Geo-Databases in the script, if needed

## Usage
* run script like: python3 dmarcGrouper.py
* Scripts:
	* dmarcAnalyzer.py: reads a bunch of xml DMARC Reports and exports the extracted data into a human readable csv format
   	* dmarcGrouper.py: additionally to the Analyzer it merges the data and groups it to asns
