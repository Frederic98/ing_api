#!/usr/bin/env python3
import datetime
import requests
import OpenSSL
import base64
import urllib.parse
import uuid
import hashlib
import pprint
import settings
import os
from typing import Union

pprinter = pprint.PrettyPrinter()
pprint = pprinter.pprint


class IngApi:
    host = 'https://api.ing.com'
    endpoints = {
        'oauth': '/oauth2/token',
        'greetings': '/greetings/single'
    }

    def __init__(self, certsfolder, clientid):
        self.certsfolder = certsfolder
        self.tls_key_file, self.tls_key = self.readcert('tls.key')
        self.tls_crt_file, self.tls_crt = self.readcert('tls.crt')
        self.sign_key_file, self.sign_key = self.readcert('signing.key')
        self.sign_crt_file, self.sign_crt = self.readcert('signing.crt')
        self.clientid = clientid
        self.session = requests.Session()
        self.session.cert = (self.tls_crt_file, self.tls_key_file)

    def readcert(self, fn):
        fn = os.path.join(self.certsfolder, fn)
        with open(fn) as f:
            return fn, f.read()

    def calc_signature(self, headers, values):
        if isinstance(headers, str):
            headers = headers.split(' ')
        signing_str = '\n'.join(['{}: {}'.format(h,v) for h,v in zip(headers, values)])
        pkey = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, self.sign_key)
        signature = OpenSSL.crypto.sign(pkey, signing_str, 'sha256')
        return base64.b64encode(signature).decode()

    def calc_digest(self, payload: Union[str, bytes]):
        if isinstance(payload, str):
            payload = payload.encode()
        return 'SHA-256=' + base64.b64encode(hashlib.sha256(payload).digest()).decode()

    def gen_reqid(self):
        return str(uuid.uuid4())

    def request_access_token(self, scopes):
        if not isinstance(scopes, str):
            scopes = ' '.join(scopes)
        body = {'grant_type': 'client_credentials',
                'scope': scopes}
        body = urllib.parse.urlencode(body)

        endpoint = self.endpoints['oauth']

        date = self.utctime_now()
        reqid = self.gen_reqid()
        digest = self.calc_digest(body)
        signature_headers = '(request-target) date digest x-ing-reqid'
        signature = self.calc_signature(signature_headers,
                                        ('post ' + endpoint, date, digest, reqid))

        headers = {'Authorization': ('Signature keyId="{}",'
                                     'algorithm="rsa-sha256",'
                                     'headers="{}",'
                                     'signature="{}"').format(self.clientid, signature_headers, signature),
                   'X-ING-ReqID': reqid,
                   'Date': date,
                   'Content-Type': 'application/x-www-form-urlencoded',
                   'Digest': digest}
        resp = self.session.post(self.host + endpoint, headers=headers, data=body)
        resp.raise_for_status()
        return resp.json()

    def request(self, method, endpoint: str, access_token: str, body='', header=None):
        date = self.utctime_now()
        digest = self.calc_digest(body)
        reqid = self.gen_reqid()
        signature_headers = '(request-target) date digest x-ing-reqid'
        signature = self.calc_signature(signature_headers,
                                        (method.lower() + ' ' + endpoint, date, digest, reqid))
        headers = {'Signature': ('keyId="{}",'
                                 'algorithm="rsa-sha256",'
                                 'headers="{}",'
                                 'signature="{}"').format(self.clientid, signature_headers, signature),
                   'Authorization': 'Bearer ' + access_token,
                   'X-ING-ReqID': reqid,
                   'Date': date,
                   'Content-Type': 'application/x-www-form-urlencoded',
                   'Digest': digest}
        if header is not None:
            headers.update(header)
        return self.session.request(method, self.host + endpoint, data=body, headers=headers)

    @staticmethod
    def utctime_now():
        return datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')


if __name__ == '__main__':
    ing = IngApi('cert/', settings.client_id)
    access_token_d = ing.request_access_token('greetings:view')
    access_token = access_token_d['access_token']
    # print(access_token)
    message = ing.request('GET', ing.endpoints['greetings'], access_token)
    # pprint(dict(message.request.headers))
    print(message.json()['message'])
