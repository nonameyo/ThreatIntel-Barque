# BARQUE

SHIPS OF THE GODS, KINGS, & OF THE PEOPLE. Web server endpoints to ship desired data across the realms

> Version 1.0.1

### About

Using [AlienVault's](https://github.com/AlienVault-OTX/OTX-Python-SDK) Open Threat Exchange to gather Threat Intel data on IPs, Domains and Hashes. This is used to enrich Blue Team logs such as firewall logs, email, DNS, AV and EDR for IOCs. This is a part of Operational Threat Intelligence program for an organization.

#### Barque Endpoints:
1.  Ping: for service status. '/server/ping'
2.  IP: to query OTX for threat intel data on specific IP(s).'/threatintel/ip'
3.  Hash: to query OTX for threat intel data on specific hashe(s). '/threatintel/hash'
4.  Domain: to query OTX for threat intel data on specific domain(s). '/threatintel/domain'
5.  CVE: to query OTX for threat intel data on specific cve(s). '/threatintel/cve'

#### Barque Use Cases:
1. Firewall logs: inbound & outbound external IPs - Enrich firewall logs with Threat Intel
2. DNS logs: Domain queries - Enrich DNS logs with Threat Intel 
3. AV/EDR logs: File hashes - Enrich AV/EDR alerts with Threat Intel info on specific hashes
4. Log enrichments can be done during log ingestion to SIEM or add Barque response to a DB for later querying
5. Research of specific IOCs using AlienVault OTX by sending POST requests
6. Server can be queried via curl/python/bash or manually by [Postman](https://www.getpostman.com/downloads/). See [configuration](https://github.com/nonameyo/ThreatIntel-Barque/blob/master/resources/Barque.postman_collection.json) file

#### Barque API response for IOCs:
1. IOC and type
2. Pulse count: how many times this specific IOC is present in OTX Pulses 
3. Associated IPs, Hashes, Domains, URLs, Emails and their counts
4. Reference Links
5. GEO info for IOC
6. CVE Details
7. Full OTX Intel dump

### Technologies

- Reverse Proxy - Nginx
- Containers - Docker

### Requirements

- docker, docker-compose

## Get up and running

Follow the steps below to get the app running

### Run Application

1.  Clone the repository

    ```
    $ git clone https://github.com/nonameyo/ThreatIntel-Barque.git
    ```

2.  Obtain API key from OTX
    - OTX requires an API key to perform searches. A free API can be obtained from their console by creating a free account. See [link](https://otx.alienvault.com/api) for how-to on AlienVault's site
    - Add your OTX API key in config.py
        ```
        $ API_KEY = 'KEY_HERE'

        └── services
            ├── investigate-server
            │   ├── app
            │   │   ├── config.py
        ```
3.  Run APP

    ```
    $ cd ThreatIntel-Barque
    $ docker-compose -f docker-compose-prod.yml build
    $ docker-compose -f docker-compose-prod.yml up -d
    ```
    Build App (--no-cache)
    ```
    $ docker-compose -f docker-compose-prod.yml build --no-cache
    ```
    Print Logs
    ```
    $ docker-compose -f docker-compose-prod.yml logs
    or
    $ docker-compose -f docker-compose-prod.yml logs {container name}
    ```

### Run Tests - server ping
- make a GET request to /server/ping. JSON respones should look like:
    ```
    {
        "status": "success",
        "message": "barque-investigate-server - active"
    }
    ```

### Use the App - ThreatIntel for IP:    
- make a POST request to /threatintel/ip with JSON in body. Should look like:
    ```
    {
        "ip":["209.99.40.222"]
    }
    ```
- cURL:
    ```
    curl -X POST http://Barque/threatintel/ip -d '{"ip":["209.99.40.222"]}'
    ```
- Python Requests:
    ```
    import requests

    url = "http://Barque/threatintel/ip"

    payload = "{\n\t\"ip\":[\"209.99.40.222\"]\n}"
    headers = {
        'Content-Type': "application/json",
        'cache-control': "no-cache"
        }
    response = requests.request("POST", url, data=payload, headers=headers)
    print(response.text)
    ```

### Use the App - ThreatIntel for Hash:    
- make a POST request to /threatintel/hash with JSON in body. Should look like:
    ```
    {
        "hash": ["db349b97c37d22f5ea1d1841e3c89eb4"]    
    }
    ```
- cURL:
    ```
    curl -X POST http://Barque/threatintel/hash -d '{"hash":["db349b97c37d22f5ea1d1841e3c89eb4"]}'
    ```
- Python Requests:
    ```
    import requests

    url = "http://Barque/threatintel/hash"

    payload = "{\n\t\"hash\":[\"db349b97c37d22f5ea1d1841e3c89eb4\"]\n}"
    headers = {
        'Content-Type': "application/json",
        'cache-control': "no-cache"
        }
    response = requests.request("POST", url, data=payload, headers=headers)
    print(response.text)
    ```

### Use the App - ThreatIntel for Domain:    
- make a POST request to /threatintel/domain with JSON in body. Should look like:
    ```
    {
        "domain": ["iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"] 
    }
    ```
- cURL:
    ```
    curl -X POST http://Barque/threatintel/domain -d '{"domain":["iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"]}'
    ```
- Python Requests:
    ```
    import requests

    url = "http://Barque/threatintel/domain"

    payload = "{\n\t\"domain\":[\"iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com\"]\n}"
    headers = {
        'Content-Type': "application/json",
        'cache-control': "no-cache"
        }
    response = requests.request("POST", url, data=payload, headers=headers)
    print(response.text)
    ```

### Use the App - ThreatIntel for CVE:    
- make a POST request to /threatintel/cve with JSON in body. Should look like:
    ```
    {
        "cve": ["CVE-2017-0143"] 
    }
    ```
- cURL:
    ```
    curl -X POST http://Barque/threatintel/cve -d '{"cve":["CVE-2017-0143"]}'
    ```
- Python Requests:
    ```
    import requests

    url = "http://Barque/threatintel/cve"

    payload = "{\n\t\"CVE-2017-0143\":[\"CVE-2017-0143\"]\n}"
    headers = {
        'Content-Type': "application/json",
        'cache-control': "no-cache"
        }
    response = requests.request("POST", url, data=payload, headers=headers)
    print(response.text)
    ```

### Directory Structure
```
├── README.md
├── docker-compose-dev.yml
├── docker-compose-prod.yml
├── resources
│   └── Barque.postman_collection.json
└── services
    ├── investigate-server
    │   ├── app
    │   │   ├── common
    │   │   │   ├── middleware.py
    │   │   │   ├── multiregex.py
    │   │   │   └── __pycache__
    │   │   │       ├── middleware.cpython-36.pyc
    │   │   │       └── multiregex.cpython-36.pyc
    │   │   ├── config.py
    │   │   ├── __init__.py
    │   │   ├── __pycache__
    │   │   │   ├── config.cpython-36.pyc
    │   │   │   ├── __init__.cpython-36.pyc
    │   │   │   └── server.cpython-36.pyc
    │   │   └── server.py
    │   ├── Dockerfile
    │   └── requirements.txt
    └── nginx
        ├── dev.conf
        ├── Dockerfile-dev
        ├── Dockerfile-prod
        └── prod.conf
```

Special thanks to [Maitray16](https://github.com/maitray16) for his work on [CodeKits](https://github.com/maitray16/CodeKits)

Thanks for reading!
Follow me on [Twitter](https://twitter.com/nonameyo_)



