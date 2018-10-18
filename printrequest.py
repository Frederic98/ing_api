import requests


def print_request(r: requests.PreparedRequest):
    print(r.method + ' ' + r.url)
    for name,value in r.headers.items():
        print('- {}: {}'.format(name,value))
    print()
    print(r.body)


def print_response(r: requests.Response):
    print('{} {}'.format(r.status_code, r.url))
    for name,value in r.headers.items():
        print('- {}: {}'.format(name,value))
    print()
    print(r.text)
