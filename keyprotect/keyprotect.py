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

import base64
import logging
import StringIO

import requests


NETLOC = "https://keyprotect.us-south.bluemix.net"
LOG = logging.getLogger(__name__)

DEBUG_CURL = False


def get_curl_cmd(req):
    curl_cmd = "curl -X%(method)s '%(url)s'" % req.__dict__
    for header, val in req.headers.items():
        curl_cmd += " -H '%s: %s'" % (header, val)
    if req.body:
        curl_cmd += " -d '%s'" % req.body
    return curl_cmd


class KeyState(object):
    # see NIST SP 800-57
    # the KeyProtect API docs only define the following for some reason
    PREACTIVATION = 0
    ACTIVE = 1
    DEACTIVATED = 3
    DESTROYED = 5


class Keys(object):

    def __init__(self, iamtoken, instance_id, verify=True):
        self._headers = {}
        self._headers['Authorization'] = "Bearer %s" % iamtoken
        self._headers['Bluemix-Instance'] = instance_id
        self.session = requests.Session()
        self.session.verify = verify

    def _validate_resp(self, resp):

        def log_resp(resp):
            resp_str = StringIO.StringIO()
            print("%s %s" % (resp.status_code, resp.reason), file=resp_str)

            for k, v in resp.headers.items():
                if k.lower() == 'authorization':
                    v = 'REDACTED'
                print("%s: %s" % (k, v), file=resp_str)

            print(resp.content, end='', file=resp_str)
            return resp_str.getvalue()

        try:
            if DEBUG_CURL:
                print(get_curl_cmd(resp.request))

            LOG.debug(log_resp(resp))

            resp.raise_for_status()
        except requests.HTTPError as http_err:
            http_err.raw_response = log_resp(resp)
            raise http_err

    def index(self):
        resp = self.session.get("%s/api/v2/keys" % NETLOC, headers=self._headers)

        self._validate_resp(resp)

        return resp.json().get('resources', [])

    def get(self, key_id):
        resp = self.session.get(
            "%s/api/v2/keys/%s" % (NETLOC, key_id),
            headers=self._headers)

        self._validate_resp(resp)

        return resp.json().get('resources')[0]

    def create(self, name, root=False):

        data = {
            "metadata": {
                "collectionType": "application/vnd.ibm.kms.key+json",
                "collectionTotal": 1},
            "resources": [
                {
                    "type": "application/vnd.ibm.kms.key+json",
                    "extractable": not root,
                    "name": name
                }
            ]
        }

        resp = self.session.post(
            "%s/api/v2/keys" % NETLOC, headers=self._headers, json=data)
        self._validate_resp(resp)
        return resp.json().get('resources')[0]

    def delete(self, key_id):
        resp = self.session.delete(
            "%s/api/v2/keys/%s" % (NETLOC, key_id), headers=self._headers)
        self._validate_resp(resp)

    def _action(self, key_id, action, jsonable):
        resp = self.session.post(
            "%s/api/v2/keys/%s" % (NETLOC, key_id),
            headers=self._headers,
            params={"action": action},
            json=jsonable)
        self._validate_resp(resp)
        return resp.json()

    def wrap(self, key_id, plaintext, aad=None):
        data = {'plaintext': base64.b64encode(plaintext)}

        if aad:
            data['aad'] = aad

        return self._action(key_id, "wrap", data)

    def unwrap(self, key_id, ciphertext, aad=None):
        data = {'ciphertext': ciphertext}

        if aad:
            data['aad'] = aad

        resp = self._action(key_id, "unwrap", data)
        return base64.b64decode(resp['plaintext'])
