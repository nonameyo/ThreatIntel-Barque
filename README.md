# BARQUE

SHIPS OF THE GODS, KING, & OF THE PEOPLE. Web server endpoints to ship desired data across the realms

> Version 1.0.0

**Barque Endpoints:**
There are 4 available endpoints
1.  Ping: for service status. '/server/ping'
2.  IP: to query OTX for threat intel data on specific IP(s).'/threatintel/ip'
3.  Hash: to query OTX for threat intel data on specific hashe(s). '/threatintel/hash'
4.  Domain: to query OTX for threat intel data on specific domain(s). '/threatintel/domain'

#### Methods of communicating with Barque:
1. Ping: GET request to http://SERVER_IP/server/ping
2. IP: POST request with JSON input as {"ip":["IP1","IP2","IP3","ETC"]}
3. Hash: POST request with JSON input as {"hash":["hash1","hash2","hash3","ETC"]}
4. Domain: POST request with JSON input as {"domain":["domain1","domain2","domain3","ETC"]}

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
    $ git clone https://github.com/nonameyo/threatintel-investigate.git
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
    $ cd threatintel-investigate
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

### Use the App - ThreatIntel for Hash:    
- make a POST request to /threatintel/hash with JSON in body. Should look like:
    ```
    {
    "hash": ["db349b97c37d22f5ea1d1841e3c89eb4"]
    }
    ```

### Use the App - ThreatIntel for Domain:    
- make a POST request to /threatintel/domain with JSON in body. Should look like:
    ```
    {
    "domain": ["iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"]
    }
    ```

### Directory Structure
```
├── README.md
├── docker-compose-dev.yml
├── docker-compose-prod.yml
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

Special thanks to Maitray S. (@forkhead10) for his work on CodeKits. Repo [here](https://github.com/maitray16/CodeKits)

Thanks for reading!

[![forthebadge](https://forthebadge.com/images/badges/check-it-out.svg)](https://forthebadge.com) [![forthebadge](https://forthebadge.com/images/badges/winter-is-coming.svg)](https://forthebadge.com)
