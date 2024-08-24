#! /usr/bin/python

import time
import requests
import random
import os
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

URLS = [
    "https://www.spiegel.de/",
    "https://www.spiegel.de/ms-1-gui",
    "https://www.spiegel.de/ms-2-txt"
]

# URLS = [
#     "https://www.nginx.com/",
#     "https://www.nginx.com/ms-1-gui",
#     "https://www.nginx.com/ms-2-txt"
# ]

user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:88.0) Gecko/20100101 Firefox/88.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36 Edg/91.0.864.54"
]

count = 14400

os.system("clear")

for i in range(count):

    for urls in URLS:
        headers = {'User-Agent': random.choice(user_agents)}
        response = requests.get(urls, headers=headers, verify=False)
        resp_status = response.status_code
        
        # see comment below --
        if urls == "http://app1.edge.de1chk1nd.de/coffee": # If stement not required - just for better formating (additional tab) ... remove if/else and just use one statement
            print(urls + " with Status:\t" + str(resp_status))
            print("User-Agent: " + str(headers.values()))
            print("")
        else:
            print(urls + " with Status:\t\t" + str(resp_status))
            print("User-Agent: " + str(headers.values()))
            print("")
        
        time.sleep(0.5)
    
    print("R E P E A T !\n")
    time.sleep(1.5)
    os.system("clear")