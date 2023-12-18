# dmarcAnalyzer
Analysis of DMARC Reports

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
