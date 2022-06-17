import json
from typing import List
from attr import attr, attrib
from pymisp import MISPAttribute, MISPEvent, MISPObject
from urllib.parse import urlparse

import logging

import vysion.client as vysion
import vysion.model as model

misperrors = {'error': 'Error'}
mispattributes = {'input': ['email', 'domain', "hostname", "url", "text", "btc", "phone-number"],
                  'format': 'misp_standard'}

# possible module-types: 'expansion', 'hover' or both
moduleinfo = {'version': '1', 'author': 'Byron Labs S.L.',
              'description': 'Enrich observables with the Vysion API',
              'module-type': ['expansion']}

# config fields that your code expects from the site admin
moduleconfig = ["apikey", "event_limit", 'proxy_host', 'proxy_port', 'proxy_username', 'proxy_password']

LOGGER = logging.getLogger('vysion')
LOGGER.setLevel(logging.INFO)
LOGGER.info("Starting Vysion")

DEFAULT_RESULTS_LIMIT = 10


def doit(client: vysion.Client, attribute: dict, limit: int = -1):

    LOGGER.info(attribute)

    misp_event = MISPEvent()
    misp_attribute: MISPAttribute = MISPAttribute()
    misp_attribute.from_dict(**attribute)
    
    attribute_type = misp_attribute.type
    attribute_value = misp_attribute.value
    
    # https://www.misp-project.org/datamodels/#types
    
    results = {}
    result = None

    LOGGER.info(attribute_type)
    LOGGER.info(attribute_type)
    if attribute_type == 'email': 
        result = client.find_email(attribute_value)
    elif attribute_type == 'domain': 
        result = client.search(attribute_value)
    # elif attribute_type == 'hostname': result = client.search(attribute_value)
    elif attribute_type == 'url': result = client.find_url(attribute_value)
    elif attribute_type == 'text': result = client.search(attribute_value)
    elif attribute_type == 'btc': result = client.search(attribute_value)
    elif attribute_type == 'phone-number': result = client.search(attribute_value)
    else:
        return {'results': results}

    # misp_object = MISPObject('phone-number')

    LOGGER.info("Processing result")
    LOGGER.info(result.hits[0].page.title)

    for hit in result.hits:

        page: model.Page = hit.page

        misp_object = MISPObject('vysion-page')

        page_id = page.id
        misp_object.add_attribute('id', type='text', value=page_id)

        url = page.url
        misp_object.add_attribute('url', type='url', value=url.build())
        
        network = url.network
        misp_object.add_attribute('network', type='text', value=network)
        
        # misp_object.add_reference(misp_attribute.uuid, 'associated-to')
        
        # TODO Add more page parameters

        misp_event.add_object(misp_object)
        
        vysion_reference_id = misp_object.uuid

        misp_event.add_attribute('domain', value=url.domain)
    
        for email in hit.email:
            misp_event.add_attribute('email', value=email.value)
 

        for btc in hit.bitcoin_address:

            misp_event.add_attribute('btc', value=btc.value)


    result = {
        'results': {
            'Object': [json.loads(object.to_json()) for object in misp_event.objects],
            'Attribute': [json.loads(attribute.to_json()) for attribute in misp_event.attributes]
        }
    }

    LOGGER.debug(result)

    return result

    


# class VirusTotalParser:
#     def __init__(self, client: vt.Client, limit: int) -> None:
#         self.client = client
#         self.limit = limit or DEFAULT_RESULTS_LIMIT
#         self.misp_event = MISPEvent()
#         self.attribute = MISPAttribute()
#         self.parsed_objects = {}
#         self.input_types_mapping = {'ip-src': self.parse_ip, 'ip-dst': self.parse_ip,
#                                     'domain': self.parse_domain, 'hostname': self.parse_domain,
#                                     'md5': self.parse_hash, 'sha1': self.parse_hash,
#                                     'sha256': self.parse_hash, 'url': self.parse_url}
#         self.proxies = None

#     @staticmethod
#     def get_total_analysis(analysis: dict, known_distributors: dict = None) -> int:
#         if not analysis:
#             return 0
#         count = sum([analysis['undetected'], analysis['suspicious'], analysis['harmless']])
#         return count if known_distributors else count + analysis['malicious']

#     def query_api(self, attribute: dict) -> None:
#         self.attribute.from_dict(**attribute)
#         self.input_types_mapping[self.attribute.type](self.attribute.value)

#     def get_result(self) -> dict:
#         event = json.loads(self.misp_event.to_json())
#         results = {key: event[key] for key in ('Attribute', 'Object') if (key in event and event[key])}
#         return {'results': results}

#     def add_vt_report(self, report: vt.Object) -> str:
#         analysis = report.get('last_analysis_stats')
#         total = self.get_total_analysis(analysis, report.get('known_distributors'))
#         permalink = f'https://www.virustotal.com/gui/{report.type}/{report.id}'

#         vt_object = MISPObject('virustotal-report')
#         vt_object.add_attribute('permalink', type='link', value=permalink)
#         detection_ratio = f"{analysis['malicious']}/{total}" if analysis else '-/-'
#         vt_object.add_attribute('detection-ratio', type='text', value=detection_ratio, disable_correlation=True)
#         self.misp_event.add_object(**vt_object)
#         return vt_object.uuid

#     def create_misp_object(self, report: vt.Object) -> MISPObject:
#         misp_object = None
#         vt_uuid = self.add_vt_report(report)

#         if report.type == 'file':
#             misp_object = MISPObject('file')
#             for hash_type in ('md5', 'sha1', 'sha256', 'tlsh',
#                               'vhash', 'ssdeep', 'imphash'):
#                 misp_object.add_attribute(hash_type,
#                                           **{'type': hash_type,
#                                              'value': report.get(hash_type)})
#         elif report.type == 'domain':
#             misp_object = MISPObject('domain-ip')
#             misp_object.add_attribute('domain', type='domain', value=report.id)
#         elif report.type == 'ip_address':
#             misp_object = MISPObject('domain-ip')
#             misp_object.add_attribute('ip', type='ip-dst', value=report.id)
#         elif report.type == 'url':
#             misp_object = MISPObject('url')
#             misp_object.add_attribute('url', type='url', value=report.url)
#         misp_object.add_reference(vt_uuid, 'analyzed-with')
#         return misp_object

#     ################################################################################
#     ####                         Main parsing functions                         #### # noqa
#     ################################################################################

#     def parse_domain(self, domain: str) -> str:
#         domain_report = self.client.get_object(f'/domains/{domain}')


#         # DOMAIN
#         domain_object = self.create_misp_object(domain_report)

#         # WHOIS
#         if domain_report.whois:
#             whois_object = MISPObject('whois')
#             whois_object.add_attribute('text', type='text', value=domain_report.whois)
#             self.misp_event.add_object(**whois_object)

#         # SIBLINGS AND SUBDOMAINS
#         for relationship_name, misp_name in [('siblings', 'sibling-of'), ('subdomains', 'subdomain')]:
#             rel_iterator = self.client.iterator(f'/domains/{domain_report.id}/{relationship_name}', limit=self.limit)
#             for item in rel_iterator:
#                 attr = MISPAttribute()
#                 attr.from_dict(**dict(type='domain', value=item.id))
#                 self.misp_event.add_attribute(**attr)
#                 domain_object.add_reference(attr.uuid, misp_name)

#         # RESOLUTIONS
#         resolutions_iterator = self.client.iterator(f'/domains/{domain_report.id}/resolutions', limit=self.limit)
#         for resolution in resolutions_iterator:
#             domain_object.add_attribute('ip', type='ip-dst', value=resolution.ip_address)

#         # COMMUNICATING, DOWNLOADED AND REFERRER FILES
#         for relationship_name, misp_name in [
#             ('communicating_files', 'communicates-with'),
#             ('downloaded_files', 'downloaded-from'),
#             ('referrer_files', 'referring')
#         ]:
#             files_iterator = self.client.iterator(f'/domains/{domain_report.id}/{relationship_name}', limit=self.limit)
#             for file in files_iterator:
#                 file_object = self.create_misp_object(file)
#                 file_object.add_reference(domain_object.uuid, misp_name)
#                 self.misp_event.add_object(**file_object)

#         # URLS
#         urls_iterator = self.client.iterator(f'/domains/{domain_report.id}/urls', limit=self.limit)
#         for url in urls_iterator:
#             url_object = self.create_misp_object(url)
#             url_object.add_reference(domain_object.uuid, 'hosted-in')
#             self.misp_event.add_object(**url_object)

#         self.misp_event.add_object(**domain_object)
#         return domain_object.uuid

#     def parse_hash(self, file_hash: str) -> str:
#         file_report = self.client.get_object(f'/files/{file_hash}')
#         file_object = self.create_misp_object(file_report)

#         # ITW URLS
#         urls_iterator = self.client.iterator(f'/files/{file_report.id}/itw_urls', limit=self.limit)
#         for url in urls_iterator:
#             url_object = self.create_misp_object(url)
#             url_object.add_reference(file_object.uuid, 'downloaded')
#             self.misp_event.add_object(**url_object)

#         # COMMUNICATING, DOWNLOADED AND REFERRER FILES
#         for relationship_name, misp_name in [
#             ('contacted_urls', 'communicates-with'),
#             ('contacted_domains', 'communicates-with'),
#             ('contacted_ips', 'communicates-with')
#         ]:
#             files_iterator = self.client.iterator(f'/files/{file_report.id}/{relationship_name}', limit=self.limit)
#             for file in files_iterator:
#                 file_object = self.create_misp_object(file)
#                 file_object.add_reference(file_object.uuid, misp_name)
#                 self.misp_event.add_object(**file_object)

#         self.misp_event.add_object(**file_object)
#         return file_object.uuid

#     def parse_ip(self, ip: str) -> str:
#         ip_report = self.client.get_object(f'/ip_addresses/{ip}')

#         # IP
#         ip_object = self.create_misp_object(ip_report)

#         # ASN
#         asn_object = MISPObject('asn')
#         asn_object.add_attribute('asn', type='AS', value=ip_report.asn)
#         asn_object.add_attribute('subnet-announced', type='ip-src', value=ip_report.network)
#         asn_object.add_attribute('country', type='text', value=ip_report.country)
#         self.misp_event.add_object(**asn_object)

#         # RESOLUTIONS
#         resolutions_iterator = self.client.iterator(f'/ip_addresses/{ip_report.id}/resolutions', limit=self.limit)
#         for resolution in resolutions_iterator:
#             ip_object.add_attribute('domain', type='domain', value=resolution.host_name)

#         # URLS
#         urls_iterator = self.client.iterator(f'/ip_addresses/{ip_report.id}/urls', limit=self.limit)
#         for url in urls_iterator:
#             url_object = self.create_misp_object(url)
#             url_object.add_reference(ip_object.uuid, 'hosted-in')
#             self.misp_event.add_object(**url_object)

#         self.misp_event.add_object(**ip_object)
#         return ip_object.uuid

#     def parse_url(self, url: str) -> str:
#         url_id = vt.url_id(url)
#         url_report = self.client.get_object(f'/urls/{url_id}')
#         url_object = self.create_misp_object(url_report)

#         # COMMUNICATING, DOWNLOADED AND REFERRER FILES
#         for relationship_name, misp_name in [
#             ('communicating_files', 'communicates-with'),
#             ('downloaded_files', 'downloaded-from'),
#             ('referrer_files', 'referring')
#         ]:
#             files_iterator = self.client.iterator(f'/urls/{url_report.id}/{relationship_name}', limit=self.limit)
#             for file in files_iterator:
#                 file_object = self.create_misp_object(file)
#                 file_object.add_reference(url_object.uuid, misp_name)
#                 self.misp_event.add_object(**file_object)

#         self.misp_event.add_object(**url_object)
#         return url_object.uuid


def get_proxy_settings(config: dict) -> dict:
    """Returns proxy settings in the requests format.
    If no proxy settings are set, return None."""
    proxies = None
    host = config.get('proxy_host')
    port = config.get('proxy_port')
    username = config.get('proxy_username')
    password = config.get('proxy_password')

    if host:
        if not port:
            misperrors['error'] = 'The vysion_proxy_host config is set, ' \
                                  'please also set the vysion_proxy_port.'
            raise KeyError
        parsed = urlparse(host)
        if 'http' in parsed.scheme:
            scheme = 'http'
        else:
            scheme = parsed.scheme
        netloc = parsed.netloc
        host = f'{netloc}:{port}'

        if username:
            if not password:
                misperrors['error'] = 'The vysion_proxy_username config is set, ' \
                                      'please also set the vysion_proxy_password.'
                raise KeyError
            auth = f'{username}:{password}'
            host = auth + '@' + host

        proxies = {
            'http': f'{scheme}://{host}',
            'https': f'{scheme}://{host}'
        }
    return proxies

def parse_error(status_code: int) -> str:
    
    status_mapping = {500: 'Vysion is blind.',
                      400: 'Incorrect request, please check the arguments.',
                      403: 'You don\'t have enough privileges to make the request.'}
    
    if status_code in status_mapping:
        return status_mapping[status_code]

    return "Vysion may not be accessible."

def handler(q=False):

    if q is False:
        return False
    
    request = json.loads(q)

    if not request.get('config') or not request['config'].get('apikey'):
        misperrors['error'] = 'A Vysion api key is required for this module.'
        return misperrors

    if not request.get('attribute'): #  or not check_input_attribute(request['attribute']):
        return {'error': f'{standard_error_message}, which should contain at least a type, a value and an uuid.'}
    
    if request['attribute']['type'] not in mispattributes['input']:
        return {'error': 'Unsupported attribute type.'}

    event_limit = request['config'].get('event_limit')
    attribute = request['attribute']
    proxy_settings = get_proxy_settings(request.get('config'))

    try:
        
        client = vysion.Client(api_key=request['config']['apikey'],
                            headers={
                                'x-tool': 'MISPModuleVysionExpansion',
                            },
                            proxy=proxy_settings['http'] if proxy_settings else None
        )
        LOGGER.info("Vysion client initialized")
        result = doit(client, attribute=attribute)
        LOGGER.info("Vysion result obtained")
        LOGGER.debug(result)

        return result
    
    except vysion.APIError as ex:
        LOGGER.error("Error in Vysion")
        LOGGER.error(ex)

        misperrors['error'] = ex.message
        return misperrors



def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
