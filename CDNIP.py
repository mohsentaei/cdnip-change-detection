#CDN IP Change Detection by Vahag
import requests
import hashlib
from pathlib import Path


cdn_ip_url = "https://www.arvancloud.com/fa/ips.txt"
#Commom CDN IP List
# ArvanCloud ==> https://www.arvancloud.com/fa/ips.txt (Default)
# CloudFlare(IPv4) ==> https://www.cloudflare.com/ips-v4
# CloudFlare(IPv6) ==> https://www.cloudflare.com/ips-v6
# Sotoon ==> https://edge.sotoon.ir/ip-list.txt
# CloudFront ==> https://ip-ranges.amazonaws.com/ip-ranges.json

healthcheckio_url = "https://hc-ping.com/414075ce-256e-4dcf-98fe-d438d452dc06" #Change this url
# If you want to get notification for the changes signup at "https://healthchecks.io/"
# After login to your dashboard you would see a link like https://hc-ping.com/XXXXXXXXXXXXXXXXXXXXXX 
# You can put it here ==> "healthcheckio_url"
#If you want to get alert you should config you healthchecksio service it is possible to send notification to almost everywhere

scan_path  = "D:\CDNIP-Change-Detection\cdn-lastscan-result.txt"
# This is a path which store your scan result 
# windows example: "D:\cdnip-change-detection\cdn-lastscan-result.txt"
# linux example: "/var/cdn-lastscan-result.txt"

#Request to CDN Provider to get New IP Addresses
livearip = requests.get(url = cdn_ip_url)
livearip=livearip.text
#Convert New IP Addresses To MD5
md=hashlib.md5(livearip.encode('utf-8')).hexdigest()
#Check If the file exist or not
file_exist = Path(scan_path)
file_exist=file_exist.is_file()
if file_exist == False:
    #If there is no file it will create new one and the scan will be start from beginning
    lastscanresult = open(scan_path, "w")
    lastscanresult.write(md)
    lastscanresult.close()
#get last previous scan result and compare
previous_scan_result = open(scan_path)
previous_scan_result = previous_scan_result.readline()
if md != previous_scan_result:
    print("""   !!!!!ALARM!!!!!
                IP Change Detection
                !!!!!ALARM!!!!!
                """)
    lastscanresult = open(scan_path, "w")
    lastscanresult.write(md)
    lastscanresult.close()
else:
    print("No IP Change Detection")
    #change user agent to get more readable in healthcheckio
    user_agent = {'User-agent': 'No IP Change Detection'}
    healthcheck_call=requests.get(url = healthcheckio_url , headers = user_agent)
