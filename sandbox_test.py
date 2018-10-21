import urllib.parse
import api_test
import pprint as PPrint

pprint = PPrint.PrettyPrinter().pprint

client_id = 'example_client_id'
ing = api_test.IngApi('cert_sb', client_id)
ing.host = 'https://api.sandbox.ing.com/'
scopes = 'create_order granting payment-requests payment-requests:view payment-requests:create payment-requests:close virtual-ledger-accounts:fund-reservation:create virtual-ledger-accounts:fund-reservation:delete virtual-ledger-accounts:balance:view'

auth_resp = ing.get('oauth2/authorization-server-url?scope=view_balance&country_code=nl', scopes)
auth_url = auth_resp.json()['location']

# Add query arguments
params = {'client_id': client_id,
          'scope': 'view_balance',
          'state': ing.generate_reqid(),
          'redirect_uri': 'http://localhost:8080/authorize',
          'response_type': 'code'}
auth_url_parts = list(urllib.parse.urlparse(auth_url))
query = dict(urllib.parse.parse_qs(auth_url_parts[4]))
query.update(params)
auth_url_parts[4] = urllib.parse.urlencode(query)
auth_url = urllib.parse.urlunparse(auth_url_parts)
print('Authorization url: {}'.format(auth_url))

authorization_code = '694d6ca9-1310-4d83-8dbb-e819c1ee6b80'

data = {'grant_type': 'authorization_code',
        'code': authorization_code,
        'redirect_uri': 'xxx'}

resp = ing.post('oauth2/token',
                scopes,
                urllib.parse.urlencode(data))
cat = resp.json()['access_token']                   # Customer Access Token
print('Customer access token: {}'.format(cat))

resp = ing.request('GET', 'v1/accounts', cat)
customer_info = resp.json()
pprint(customer_info)
