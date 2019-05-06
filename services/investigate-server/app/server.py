import os
import json
import falcon
import string
import socket
import secrets
import logging
import requests
import ast
import re
from datetime import datetime
from app.config import BaseConfig
from requests.auth import HTTPBasicAuth
from app.common.middleware import Middelware
from OTXv2 import OTXv2
import IndicatorTypes
from app.common.multiregex import MultiRegex
import ipaddress


class SanityCheck(object):
    """
    Endpoint to check health of application.
    Methods : [GET]
    Params:
        -
    Returns:
        string: msg
    """

    def on_get(self, req, resp):
        resp.status = falcon.HTTP_200
        response = {'status': 'success',
                    'message': 'barque-investigate-server - active'}
        resp.body = json.dumps(response)


class GetThreatIntelIP(object):
    """
    Endpoint to get threat intel data on 1 IP from user.
    Methods : [post]
    Params:
        "ip":["ip1", "ip2"]
    Returns:
        LIST - OTX threat intel results for IPs
    """

    def __init__(self):
        self.otx = OTXv2(BaseConfig.API_KEY, server=BaseConfig.OTX_URL)
        self.multiregex = MultiRegex()

    def on_post(self, req, resp):
        result = []
        data = req.context['body']
        ip_list = data['ip']

        for ip in ip_list:
            _type, key = self.multiregex(ip)
            if _type == "Invalid":
                data = {'key': ip, 'msg': "Invalid IP"}
                result.append(data)
            else:
                try:
                    ip_type = "IndicatorTypes." + _type
                    otx_ip = {}
                    allmalware = []
                    alltags = []
                    flattendtags = []
                    allurllist = []
                    alldomainsinurllist = []
                    allipsinurllist = []
                    otx_data = str(self.otx.get_indicator_details_full(
                        eval(ip_type), ip))
                    otxdict = ast.literal_eval(otx_data)
                    otx_ip["key"] = ip
                    otx_ip['type'] = otxdict.get(
                        'general', {}).get('type', "N/A")
                    otx_ip['intel_status'] = "success"
                    otx_ip['city'] = otxdict.get(
                        'geo', {}).get('city', "N/A") or "N/A"
                    otx_ip['country'] = otxdict.get(
                        'geo', {}).get('country_name', "N/A")
                    otx_ip['pulse_count'] = otxdict.get(
                        'general', {}).get('pulse_info', {}).get('count', 0)
                    otx_ip['url_count'] = otxdict.get(
                        'url_list', {}).get('full_size', 0)
                    otx_ip['malware_count'] = otxdict.get(
                        'malware', {}).get('size', 0) or 0
                    otx_ip['references'] = otxdict.get(
                        'general', {}).get('pulse_info', {}).get('references', "N/A")
                    in_malware = otxdict.get(
                        'malware', {}).get('data', {})
                    in_tags = otxdict.get('general', {}).get(
                        'pulse_info', {}).get('pulses', {})
                    in_url_list = otxdict.get(
                        'url_list', {}).get('url_list', {})

                    for i in in_tags:
                        alltags.append(i.get('tags'))
                    for tag in alltags:
                        for val in tag:
                            flattendtags.append(val)

                    for i in in_malware:
                        allmalware.append(i.get('hash', "N/A"))

                    for i in in_url_list:
                        alldomainsinurllist.append(i.get('hostname', "N/A"))
                        allurllist.append(i.get('url', "N/A"))
                        allipsinurllist.append(i.get('result', {}).get(
                            'urlworker', {}).get('ip', ""))

                    otx_ip['tags'] = list(set(flattendtags))
                    otx_ip['associated_malware'] = list(set(allmalware))
                    otx_ip['associated_ips'] = [
                        item for item in list(set(allipsinurllist)) if item]
                    otx_ip['associated_hostnames'] = list(
                        set(alldomainsinurllist))
                    otx_ip['associated_urls'] = list(set(allurllist))
                    otx_ip["intel"] = otxdict
                    result.append(otx_ip)
                except:
                    data = {'key': ip, 'msg': 'No Data Found',
                            'intel_status': "fail", 'type': _type}
                    result.append(data)

        resp.status = falcon.HTTP_200
        resp.body = json.dumps(result)


class GetThreatIntelHash(object):
    """
    Endpoint to get threat intel data on hashes from user.
    Methods : [post]
    Params:
        "hash":["HASH_1", "HASH_2"]
    Returns:
        LIST - OTX threat intel results for hashes
    """

    def __init__(self):
        self.otx = OTXv2(BaseConfig.API_KEY, server=BaseConfig.OTX_URL)
        self.multiregex = MultiRegex()

    def on_post(self, req, resp):
        result = []
        data = req.context['body']
        hash_list = data['hash']

        for _hash in hash_list:
            _type, key = self.multiregex(_hash)
            if _type == 'Invalid':
                data = {'key': _hash, 'msg': "Invalid Hash"}
                result.append(data)
            else:
                try:
                    hash_type = "IndicatorTypes." + _type
                    otx_hash = {}
                    alltags = []
                    flattendtags = []
                    real_ips = []
                    otx_data = str(
                        self.otx.get_indicator_details_full(eval(hash_type), _hash))
                    otxdict = ast.literal_eval(otx_data)
                    otx_hash["key"] = _hash
                    otx_hash['type'] = otxdict.get(
                        'general', {}).get('type', "N/A")
                    otx_hash['intel_status'] = "success"
                    otx_hash['pulse_count'] = otxdict.get(
                        'general', {}).get('pulse_info', {}).get('count', 0)
                    otx_hash['sha1'] = otxdict.get('analysis', {}).get(
                        'analysis', {}).get('info', {}).get('results', {}).get('sha1', "N/A")
                    otx_hash['sha256'] = otxdict.get('analysis', {}).get(
                        'analysis', {}).get('info', {}).get('results', {}).get('sha256', "N/A")
                    otx_hash['md5'] = otxdict.get('analysis', {}).get(
                        'analysis', {}).get('info', {}).get('results', {}).get('md5', "N/A")
                    otx_hash['file_class'] = otxdict.get('analysis', {}).get('analysis', {}).get(
                        'info', {}).get('results', {}).get('file_class', "N/A")
                    otx_hash['file_type'] = otxdict.get('analysis', {}).get('analysis', {}).get(
                        'info', {}).get('results', {}).get('file_type', "N/A")
                    in_tags = otxdict.get('general', {}).get(
                        'pulse_info', {}).get('pulses', {})

                    for i in in_tags:
                        alltags.append(i.get('tags'))
                    for tag in alltags:
                        for val in tag:
                            flattendtags.append(val)

                    otx_hash['tags'] = list(set(flattendtags))

                    if 'exiftool' in otxdict['analysis']['analysis']['plugins']:
                        i_exfiltool = otxdict.get('analysis', {}).get('analysis', {}).get(
                            'plugins', {}).get('exiftool', {}).get('results', {})
                        otx_hash['exiftool_original_file_name'] = i_exfiltool.get(
                            "EXE:OriginalFileName", "N/A")
                        otx_hash['exiftool_product_name'] = i_exfiltool.get(
                            "EXE:ProductName", "N/A")
                        otx_hash['exiftool_file_description'] = i_exfiltool.get(
                            "EXE:FileDescription", "N/A")

                    if 'msdefender' in otxdict['analysis']['analysis']['plugins']:
                        i_exfiltool = otxdict.get('analysis', {}).get('analysis', {}).get(
                            'plugins', {}).get('msdefender', {}).get('results', {})
                        otx_hash['ms_defender_finding'] = i_exfiltool.get(
                            "detection", "N/A")
                        otx_hash['ms_defender_notes'] = i_exfiltool.get(
                            "alerts", "N/A")

                    if 'avast' in otxdict['analysis']['analysis']['plugins']:
                        i_exfiltool = otxdict.get('analysis', {}).get('analysis', {}).get(
                            'plugins', {}).get('avast', {}).get('results', {})
                        otx_hash['avast_finding'] = i_exfiltool.get(
                            "detection", "N/A")
                        otx_hash['avast_notes'] = i_exfiltool.get(
                            "alerts", "N/A")

                    if 'metaextract' in otxdict['analysis']['analysis']['plugins']:
                        i_exfiltool = otxdict.get('analysis', {}).get('analysis', {}).get(
                            'plugins', {}).get('metaextract', {}).get('results', {})

                        # find valid associated IPs in bad hash
                        for x in i_exfiltool.get("ips", []):
                            try:
                                ipaddress.ip_address(x)
                                real_ips.append(x)
                            except ValueError:
                                pass

                        otx_hash['associated_ips'] = real_ips
                        otx_hash['associated_urls'] = i_exfiltool.get(
                            "urls", [])
                        otx_hash['associated_emails'] = i_exfiltool.get(
                            "emails", [])

                    if 'cuckoo' in otxdict['analysis']['analysis']['plugins']:
                        i_exfiltool = otxdict.get('analysis', {}).get('analysis', {}).get(
                            'plugins', {}).get('cuckoo', {}).get('result', {}).get('virustotal', {})
                        otx_hash['vt_positives'] = i_exfiltool.get(
                            "positives", 0)
                        otx_hash['vt_total'] = i_exfiltool.get(
                            "total", 0)
                        otx_hash['vt_link'] = i_exfiltool.get(
                            "permalink", "N/A")

                    otx_hash["intel"] = otxdict
                    result.append(otx_hash)
                except:
                    data = {'key': _hash, 'msg': "No Data Found",
                            'intel_status': "fail", 'type': _type}
                    result.append(data)

        resp.status = falcon.HTTP_200
        resp.body = json.dumps(result)


class GetThreatIntelDomain(object):
    """
    Endpoint to get threat intel data on domains from user.
    Methods : [post]
    Params:
        "domain": ["domain1.com", "domain2.com"]
    Returns:
        LIST - OTX threat intel results for domains
    """

    def __init__(self):
        self.otx = OTXv2(BaseConfig.API_KEY, server=BaseConfig.OTX_URL)
        self.multiregex = MultiRegex()

    def on_post(self, req, resp):
        result = []
        data = req.context['body']
        domain_list = data['domain']

        for domain in domain_list:
            _type, key = self.multiregex(domain)
            if _type == 'Invalid':
                data = {'key': domain, 'msg': "Invalid Domain"}
                result.append(data)
            else:
                try:
                    domain_type = "IndicatorTypes." + _type
                    otx_domain = {}
                    allmalware = []
                    alltags = []
                    flattendtags = []
                    allurllist = []
                    alldomainsinurllist = []
                    allipsinurllist = []
                    otx_data = str(
                        self.otx.get_indicator_details_full(eval(domain_type), domain))
                    otxdict = ast.literal_eval(otx_data)

                    otx_domain['key'] = domain
                    otx_domain['type'] = otxdict.get(
                        'general', {}).get('type', "N/A")
                    otx_domain['intel_status'] = "success"
                    otx_domain['city'] = otxdict.get(
                        'geo', {}).get('city', "N/A") or "N/A"
                    otx_domain['country'] = otxdict.get(
                        'geo', {}).get('country_name', "N/A")
                    otx_domain['pulse_count'] = otxdict.get(
                        'general', {}).get('pulse_info', {}).get('count', 0)
                    otx_domain['url_count'] = otxdict.get(
                        'url_list', {}).get('actual_size', 0) or 0
                    otx_domain['malware_count'] = otxdict.get(
                        'malware', {}).get('size', 0) or 0
                    otx_domain['references'] = otxdict.get(
                        'general', {}).get('pulse_info', {}).get('references', "N/A")

                    in_url_list = otxdict.get(
                        'url_list', {}).get('url_list', {})
                    in_malware_list = otxdict.get(
                        'malware', {}).get('data', [])
                    in_tags = otxdict.get('general', {}).get(
                        'pulse_info', {}).get('pulses', {})

                    for i in in_tags:
                        alltags.append(i.get('tags'))
                    for tag in alltags:
                        for val in tag:
                            flattendtags.append(val)

                    for i in in_malware_list:
                        allmalware.append(i.get('hash', "N/A"))

                    for i in in_url_list:
                        alldomainsinurllist.append(i.get('hostname', "N/A"))
                        allurllist.append(i.get('url', "N/A"))
                        allipsinurllist.append(i.get('result', {}).get(
                            'urlworker', {}).get('ip', ""))

                    otx_domain['tags'] = list(set(flattendtags))
                    otx_domain['associated_malware'] = list(set(allmalware))
                    otx_domain['associated_ips'] = [
                        item for item in list(set(allipsinurllist)) if item]
                    otx_domain['associated_hostnames'] = list(
                        set(alldomainsinurllist))
                    otx_domain['associated_urls'] = list(set(allurllist))
                    otx_domain["intel"] = otxdict
                    result.append(otx_domain)
                except:
                    data = {'key': domain, 'msg': "No Data Found",
                            'intel_status': "fail", 'type': _type}
                    result.append(data)

        resp.status = falcon.HTTP_200
        resp.body = json.dumps(result)


def initialize() -> falcon.API:
    app = falcon.API(middleware=[Middelware()])
    app.add_route('/server/ping', SanityCheck())
    app.add_route('/threatintel/ip', GetThreatIntelIP())
    app.add_route('/threatintel/hash', GetThreatIntelHash())
    app.add_route('/threatintel/domain', GetThreatIntelDomain())
    return app


def run(*args, **kwargs) -> falcon.API:
    return initialize()
