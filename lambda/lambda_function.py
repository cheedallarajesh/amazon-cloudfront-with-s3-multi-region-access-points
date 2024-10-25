# With the help of GitHub Copilot, updated to address error: [module 'botocore.crt' has no attribute 'auth']

import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
import logging
import os

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger()

# Externalize configuration
FAILOVER_HEADER = os.getenv('FAILOVER_HEADER', 'originTypeFailover')
CF_READ_ONLY_HEADERS_LIST = [h.lower() for h in os.getenv('CF_READ_ONLY_HEADERS_LIST', 'Accept-Encoding,Content-Length,If-Modified-Since,If-None-Match,If-Range,If-Unmodified-Since,Transfer-Encoding,Via').split(',')]

class SigV4Wrapper:
    def __init__(self):
        self._session = boto3.Session()
        
    def get_auth_headers(self, method, endpoint, data, region, service, headers):
        logger.debug(f"Constructing SigV4 auth headers for {method} {endpoint}")
        if headers is None:
            headers = {}
        credentials = self._session.get_credentials().get_frozen_credentials()
        request = AWSRequest(method=method, url=endpoint, data=data, headers=headers)
        SigV4Auth(credentials, service, region).add_auth(request)
        prepped = request.prepare()
        return prepped.headers

def handle_failover_request(request):
    if FAILOVER_HEADER in request['headers']:
        return request
    return None

def construct_endpoint(request):
    query_string = request.get('querystring', '')
    endpoint = f"https://{request['origin']['custom']['domainName']}{request['uri']}"
    if query_string:
        endpoint += f"?{query_string}"
    return endpoint, query_string

def handle_request_body(request):
    if 'body' in request:
        if request['body'].get('inputTruncated', False):
            return {
                'status': '413',
                'statusDescription': 'Payload Too Large'
            }, None
        return None, request['body'].get('data', '')
    return None, None

def filter_headers(headers):
    cf_read_only_headers = {}
    for header in CF_READ_ONLY_HEADERS_LIST:
        if header in headers:
            cf_read_only_headers[header] = headers[header][0]['value']
    return cf_read_only_headers

def lambda_handler(event, context):
    request = event['Records'][0]['cf']['request']
    logger.debug(f"Received request: {request}")
    # Check if this is a failover request
    failover_response = handle_failover_request(request)
    if failover_response:
        logger.debug(f"Failover request detected, returning {failover_response}")
        return failover_response

    method = request["method"]
    endpoint, query_string = construct_endpoint(request)
    
    # Handle request body for methods like PUT, POST
    error_response, data = handle_request_body(request)
    if error_response:
        logger.warning(f"Error during request body handling: {error_response}")
        return error_response
    
    headers = request["headers"]
    cf_read_only_headers = filter_headers(headers)

    # Sign the request
    try:
        logger.debug(f"Signing request for {method} {endpoint}")
        auth_headers = SigV4Wrapper().get_auth_headers(method, endpoint, data, '*', 's3', cf_read_only_headers)
    except Exception as e:
        logger.error(f"Error during SigV4 signing: {str(e)}")
        return {
            'status': '500',
            'statusDescription': 'Internal Server Error'
        }

    # Remove 'X-Amz-Cf-Id' header as CloudFront will set it
    auth_headers.pop('X-Amz-Cf-Id', None)

    cf_headers = {}
    # Add SigV4 auth headers in the CloudFront expected data structure
    for k, v in auth_headers.items():
        cf_headers[k.lower()] = [{'key': k, 'value': v}]

    # Override headers to only include the ones expected by S3 Multi-Region Access Point
    request['headers'] = cf_headers

    # Preserve the query string
    if query_string:
        request['querystring'] = query_string

    logger.debug(f"Returning request: {request}")
    return request
