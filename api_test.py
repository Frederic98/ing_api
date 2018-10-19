#!/usr/bin/env python3
import datetime
import requests
import OpenSSL
import base64
import urllib.parse
import uuid
import hashlib
import os
from typing import Union
import logging

logger = logging.getLogger(__name__)


class IngApi:
    host = 'https://api.ing.com'
    endpoints = {
        'oauth': '/oauth2/token',
        'greetings': '/greetings/single'
    }

    def __init__(self, certsfolder, clientid):
        self.certsfolder = certsfolder
        self.tls_key_file, self.tls_key = self.read_certificate('tls.key')
        self.tls_crt_file, self.tls_crt = self.read_certificate('tls.crt')
        self.sign_key_file, self.sign_key = self.read_certificate('signing.key')
        self.sign_crt_file, self.sign_crt = self.read_certificate('signing.crt')
        self.clientid = clientid
        self.session = requests.Session()
        self.session.cert = (self.tls_crt_file, self.tls_key_file)

    def read_certificate(self, fn):
        fn = os.path.join(self.certsfolder, fn)
        with open(fn) as f:
            return fn, f.read()

    def calculate_signature(self, signing_str: str):
        pkey = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, self.sign_key)
        signature = OpenSSL.crypto.sign(pkey, signing_str, 'sha256')
        return base64.b64encode(signature).decode()

    @staticmethod
    def calculate_digest(payload: Union[str, bytes]):
        """Calculate the SHA-256 hash of the payload, base64 encoded."""
        if isinstance(payload, str):
            payload = payload.encode()
        return 'SHA-256=' + base64.b64encode(hashlib.sha256(payload).digest()).decode()

    @staticmethod
    def generate_reqid():
        """Create a random RequestID for the X-ING-ReqID header"""
        return str(uuid.uuid4())

    def create_request(self, method, endpoint, headers=None, body=''):
        rheaders = {
            'Date': self.utctime_now(),
            'X-ING-ReqID': self.generate_reqid(),
            'Digest': self.calculate_digest(body)
        }
        if headers is not None:
            rheaders.update(headers)
        request = requests.Request(method=method, url=urllib.parse.urljoin(self.host, endpoint), headers=rheaders, data=body)
        return self.session.prepare_request(request)

    def sign_request(self, request: requests.PreparedRequest, headers='(request-target) date digest x-ing-reqid'):
        """Sign the request using the provided headers. When neccesary, authorize the request first."""
        sign_strings = []
        for header in headers.split(' '):
            if header == '(request-target)':
                value = '{} {}'.format(request.method, request.path_url).lower()
            else:
                value = request.headers[header]
            sign_strings.append('{}: {}'.format(header.lower(), value))
        sign_string = '\n'.join(sign_strings)

        signature = self.calculate_signature(sign_string)
        signature = 'keyId="{}",algorithm="rsa-sha256",headers="{}",signature="{}"'\
                        .format(self.clientid, headers, signature)
        if 'Authorization' in request.headers:
            # Authorization already present, place signature in Signature header
            request.headers['Signature'] = signature
        else:
            # Authorization not in header, authorize using the signature
            request.headers['Authorization'] = 'Signature ' + signature
        return request

    @staticmethod
    def authorize_request(request: requests.PreparedRequest, authorization):
        """Authorize the request with the provided authorization.
           The authorization argument can either be a string of the access token,
            or a dict with the keys 'access_token' and 'token_type'"""
        if isinstance(authorization, str):
            access_token = authorization
            token_type = 'Bearer'
        else:
            access_token = authorization['access_token']
            token_type = authorization['token_type']
        authorization_str = '{} {}'.format(token_type, access_token)
        request.headers['Authorization'] = authorization_str
        return request

    def request_access_token(self, scopes):
        """Request an access token for the specified scope(s).
           Scopes can either be a string with a single scope, or a list of scopes"""
        if not isinstance(scopes, str):
            scopes = ' '.join(scopes)
        body = {'grant_type': 'client_credentials',
                'scope': scopes}
        body = urllib.parse.urlencode(body)

        endpoint = self.endpoints['oauth']
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        request = self.create_request('POST', endpoint, headers, body)

        signature_headers = '(request-target) date digest x-ing-reqid'
        self.sign_request(request, signature_headers)

        resp = self.session.send(request)
        resp.raise_for_status()
        return resp.json()

    def request(self, method, endpoint: str, access_token: str, body='', headers=None):
        rheaders = {'Content-Type': 'application/x-www-form-urlencoded'}
        if headers is not None:
            rheaders.update(headers)
        request = self.create_request(method, endpoint, rheaders, body)

        self.authorize_request(request, access_token)
        signature_headers = '(request-target) date digest x-ing-reqid'
        self.sign_request(request, signature_headers)

        resp = self.session.send(request)
        return resp

    def get(self, endpoint, scopes, body='', headers=None):
        token = self.request_access_token(scopes)
        return self.request('GET', endpoint, token, body, headers)

    def post(self, endpoint, scopes, body='', headers=None):
        token = self.request_access_token(scopes)
        return self.request('POST', endpoint, token, body, headers)

    @staticmethod
    def utctime_now():
        """Return a string with the current time formatted according to the HTTP specifications
            https://tools.ietf.org/html/rfc7231#section-7.1.1.2"""
        return datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')


if __name__ == '__main__':
    import pprint
    import settings

    logging.basicConfig(format="%(asctime)-15s %(levelname)-8s %(name)-15s %(message)s", level=logging.DEBUG)
    pprinter = pprint.PrettyPrinter()
    pprint = pprinter.pprint

    ing = IngApi('cert/', settings.client_id)
    greeting_response = ing.get(ing.endpoints['greetings'], 'greetings:view')
    print(greeting_response.json()['message'])
