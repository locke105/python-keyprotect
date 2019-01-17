# Copyright 2018 Mathew Odden <mathewrodden@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import print_function

import json
import logging
import pprint

from http.client import HTTPConnection, HTTPSConnection
from urllib.parse import urlencode, urlparse, urlunsplit


LOG = logging.getLogger(__name__)


def request(method, url, body=None, data=None, headers=None):
    LOG.debug("URL:" + url)

    headers = headers if headers else {}

    if data:
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
        body = urlencode(data)

    parts = urlparse(url)

    if parts.scheme == 'https':
        conn = HTTPSConnection(parts.netloc)
    else:
        conn = HTTPConnection(parts.netloc)
    path = urlunsplit(('', '', parts.path, parts.query, parts.fragment))

    LOG.debug(get_curl(method, url, headers))

    LOG.info('httplib %s %s' % (method, path))
    LOG.debug('headers=%s' % pprint.pformat(headers))
    LOG.debug('body=%r' % body)
    conn.request(method, path, body=body, headers=headers)
    resp = conn.getresponse()

    LOG.info('httplib response - %s %s' % (resp.status, resp.reason))

    return resp


def get_curl(method, url, headers):
    header_strs = []
    for k, v in headers.items():
        header_strs.append('-H "%s: %s"' % (k, v))

    header_str = ' '.join(header_strs)

    curl_str = 'curl -v -X%(method)s %(headers)s "%(url)s"' % {
        'method': method,
        'headers': header_str,
        'url': url
    }

    return curl_str


def auth(username=None, password=None, apikey=None, bss_account=None):
    """
    Makes a authentication request to the IAM api
    :param username: User
    :param password: Password
    :param apikey: API Key
    :param bss_account: Billing Account
    :return: Response
    """
    api_path = '/oidc/token'
    api_endpoint = 'https://iam.ng.bluemix.net%s' % api_path

    # HTTP Headers
    headers = {
        'Authorization': 'Basic Yng6Yng=',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json'
    }

    # HTTP Payload
    data = {
        'response_type': 'cloud_iam',
        'uaa_client_id': 'cf',
        'uaa_client_secret': ''
    }

    # Setup grant type
    if apikey:
        data['grant_type'] = 'urn:ibm:params:oauth:grant-type:apikey'
        data['apikey'] = apikey
    elif username and password:
        data['grant_type'] = 'password'
        data['username'] = username
        data['password'] = password
    else:
        raise ValueError("Must specify one of username/password or apikey!")


    encoded = urlencode(data)
    resp = request('POST', api_endpoint, body=encoded, headers=headers)

    if resp.status == 200:
        jsonable = json.loads(resp.read())
        return jsonable

    return resp.read()


def get_orgs(bearer_token):
    api_endpoint = 'https://api.ng.bluemix.net/v2/organizations'

    headers = {
        'Content-Type': 'application/x-www-form-urlencoded;charset=utf',
        'Authorization': 'Bearer %s' % bearer_token,
        'Accept': 'application/json;charset=utf-8'
    }

    resp = request('GET', api_endpoint, headers=headers)
    return resp.read()


def get_spaces(bearer_token, spaces_path):
    api_endpoint = 'https://api.ng.bluemix.net%s' % spaces_path

    headers = {
        'Content-Type': 'application/x-www-form-urlencoded;charset=utf',
        'Authorization': 'Bearer %s' % bearer_token,
        'Accept': 'application/json;charset=utf-8'
    }

    resp = request('GET', api_endpoint, headers=headers)
    return resp.read()


def find_space_and_org(bearer_token, org_name, space_name):
    org_resp = get_orgs(bearer_token)
    org_data = json.loads(org_resp)

    for org in org_data['resources']:
        if org_name == org.get('entity', {}).get('name'):
            org_info = org
            break

    space_resp = get_spaces(bearer_token, org_info['entity']['spaces_url'])
    space_data = json.loads(space_resp)

    for space in space_data['resources']:
        if space_name == space.get('entity', {}).get('name'):
            space_info = space
            break

    return org_info, space_info
