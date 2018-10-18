#!/usr/bin/env python3

# First test script to interface with the ING API
# Currently, it requests an access token
import datetime
import requests
import OpenSSL
import base64
import urllib.parse
import uuid
import hashlib
from printrequest import print_request, print_response
import settings


client_id = settings.client_id
oauth_endpoint = 'https://api.ing.com/oauth2/token'
certfolder = 'cert/'
tlscert = certfolder + 'tls_public.crt'
tlskey = certfolder + 'tls.key'
signcert = certfolder + 'signing.crt'
signkey = certfolder + 'signing.key'
signpass = None


def calc_signature(method, path, date, digest, reqid, signkey, signpass=None):
    signing_str = """(request-target): {method} {path}
date: {date}
digest: {digest}
x-ing-reqid: {reqid}""".format(**locals())
    with open(signkey) as signkey_f:
        signkey_s = signkey_f.read()
    pkey = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, signkey_s, signpass)
    signature = OpenSSL.crypto.sign(pkey, signing_str, 'sha256')
    return base64.b64encode(signature).decode()


req_data = {'grant_type': 'client_credentials',
            'scope': 'greetings:view'}
req_body = urllib.parse.urlencode(req_data)

req_date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
req_id = str(uuid.uuid4())
req_hasher = hashlib.sha256()
req_hasher.update(req_body.encode())
req_digest = "SHA-256=" + base64.b64encode(req_hasher.digest()).decode()
req_signature = calc_signature('post', '/oauth2/token', req_date, req_digest, req_id, signkey, signpass)

headers = {'Authorization': 'Signature keyId="{}",'\
                            'algorithm="rsa-sha256",'\
                            'headers="(request-target) date digest x-ing-reqid",'\
                            'signature="{}"'.format(client_id, req_signature),
           'X-ING-ReqID': req_id,
           'Date': req_date,
           'Content-Type': 'application/x-www-form-urlencoded',
           'Digest': req_digest}

resp = requests.post(oauth_endpoint, headers=headers, data=req_body, cert=(tlscert, tlskey))

print('*'*10 + ' Request ' + '*'*10)
print_request(resp.request)
print('*'*10 + ' Response ' + '*'*10)
print_response(resp)

print('Success!' if 200 <= resp.status_code < 300 else 'Fail!')
