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
        keyid = self.gen_reqid()
        digest = 'SHA-256=' + base64.b64encode(hashlib.sha256(body.encode()).digest()).decode()
        signature_headers = '(request-target) date digest x-ing-reqid'
        signature = self.calc_signature(signature_headers,
                                        ('post ' + endpoint, date, digest, keyid))

        headers = {'Authorization': ('Signature keyId="{}",'
                                     'algorithm="rsa-sha256",'
                                     'headers="{}",'
                                     'signature="{}"').format(self.clientid, signature_headers, signature),
                   'X-ING-ReqID': keyid,
                   'Date': date,
                   'Content-Type': 'application/x-www-form-urlencoded',
                   'Digest': digest}
        resp = requests.post(self.host + endpoint, headers=headers, data=body, cert=(self.tls_crt_file, self.tls_key_file))
        resp.raise_for_status()
        return resp.json()

    @staticmethod
    def utctime_now():
        return datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')


if __name__ == '__main__':
    ing = IngApi('cert/', settings.client_id)
    pprint(ing.request_access_token('greetings:view'))
