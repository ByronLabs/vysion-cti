import json
from pymisp import MISPAttribute, MISPEvent
from urllib.parse import urlparse

import logging

import vysion.client as vysion

import vysion.dto as dto
from vysion.dto.util import MISPProcessor

misperrors = {"error": "Error"}
mispattributes = {
    "input": [
        "email",
        "domain",
        "hostname",
        "url",
        "text",
        "btc",
        "phone-number",
        "target-org",
    ],
    "format": "misp_standard",
}

# possible module-types: 'expansion', 'hover' or both
moduleinfo = {
    "version": "1",
    "author": "Byron Labs",
    "description": "Enrich observables with the Vysion API",
    "module-type": ["expansion"],
}

# config fields that your code expects from the site admin
moduleconfig = [
    "apikey",
    "event_limit",
    "proxy_host",
    "proxy_port",
    "proxy_username",
    "proxy_password",
]

LOGGER = logging.getLogger("vysion")
LOGGER.setLevel(logging.INFO)
LOGGER.info("Starting Vysion")

DEFAULT_RESULTS_LIMIT = 10


def get_proxy_settings(config: dict) -> dict:
    """Returns proxy settings in the requests format.
    If no proxy settings are set, return None."""
    proxies = None
    host = config.get("proxy_host")
    port = config.get("proxy_port")
    username = config.get("proxy_username")
    password = config.get("proxy_password")

    if host:
        if not port:
            misperrors["error"] = (
                "The vysion_proxy_host config is set, "
                "please also set the vysion_proxy_port."
            )
            raise KeyError
        parsed = urlparse(host)
        if "http" in parsed.scheme:
            scheme = "http"
        else:
            scheme = parsed.scheme
        netloc = parsed.netloc
        host = f"{netloc}:{port}"

        if username:
            if not password:
                misperrors["error"] = (
                    "The vysion_proxy_username config is set, "
                    "please also set the vysion_proxy_password."
                )
                raise KeyError
            auth = f"{username}:{password}"
            host = auth + "@" + host

        proxies = {"http": f"{scheme}://{host}", "https": f"{scheme}://{host}"}
    return proxies


def parse_error(status_code: int) -> str:

    status_mapping = {
        500: "Vysion is blind.",
        400: "Incorrect request, please check the arguments.",
        403: "You don't have enough privileges to make the request.",
    }

    if status_code in status_mapping:
        return status_mapping[status_code]

    return "Vysion may not be accessible."


def handler(q=False):

    if q is False:
        return False

    request = json.loads(q)

    if not request.get("config") or not request["config"].get("apikey"):
        misperrors["error"] = "A Vysion api key is required for this module."
        return misperrors

    if not request.get("attribute"):
        #  or not check_input_attribute(request['attribute']):
        return {
            "error": f"{standard_error_message}, which should contain at least a type, a value and an uuid."
        }

    if request["attribute"]["type"] not in mispattributes["input"]:
        return {"error": "Unsupported attribute type."}

    # event_limit = request["config"].get("event_limit")
    attribute = request["attribute"]
    proxy_settings = get_proxy_settings(request.get("config"))

    try:

        client = vysion.Client(
            api_key=request["config"]["apikey"],
            headers={
                "x-tool": "MISPModuleVysionExpansion",
            },
            proxy=proxy_settings["http"] if proxy_settings else None,
        )

        LOGGER.debug(attribute)

        misp_attribute = MISPAttribute()
        misp_attribute.from_dict(**attribute)

        attribute_type = misp_attribute.type
        attribute_value = misp_attribute.value

        # https://www.misp-project.org/datamodels/#types

        LOGGER.debug(attribute_type)
        LOGGER.debug(attribute_type)

        result = None

        # TODO Segregar funcionalidad por tipo
        if attribute_type == "email":
            result = client.find_email(attribute_value)
        elif attribute_type == "domain":
            result = client.search(attribute_value)  # TODO
        # elif attribute_type == 'hostname': result = client.search(attribute_value)
        elif attribute_type == "url":
            result = client.search(
                attribute_value
            )  # TODO result = client.find_url(attribute_value)
        elif attribute_type == "text":
            result = client.search(attribute_value)
        elif attribute_type == "target-org":
            result = client.search(attribute_value, exact=True)
        elif attribute_type == "btc":
            result = client.search(attribute_value)  # TODO
        elif attribute_type == "phone-number":
            result = client.search(attribute_value)  # TODO

        if result is None:
            return {"results": {}}
        elif isinstance(result, dto.VysionError):
            LOGGER.error(str(result))
            return {"results": {}}

        p = MISPProcessor()
        misp_event: MISPEvent = p.process(result, ref_attribute=misp_attribute)

        LOGGER.info("Vysion client initialized")

        LOGGER.info("Vysion result obtained")

        return {
            "results": {
                "Object": [
                    json.loads(object.to_json()) for object in misp_event.objects
                ],
                "Attribute": [
                    json.loads(attribute.to_json())
                    for attribute in misp_event.attributes
                ], 
                # TODO Cómo hacer que las tags se representen en MISP
                "Tag": [
                    json.loads(tag.to_json())
                    for tag in misp_event.tags
                ]
            }
        }

    except vysion.APIError as ex:

        LOGGER.error("Error in Vysion")
        LOGGER.error(ex)

        misperrors["error"] = ex.message
        return misperrors


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
