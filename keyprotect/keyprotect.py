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

import StringIO

import requests

NETLOC = "https://keyprotect.us-south.bluemix.net"

class Keys(object):

    def __init__(self, iamtoken, instance_id):
        self._headers = {}
        self._headers['authorization'] = "Bearer %s" % iamtoken
        self._headers['bluemix-instance'] = instance_id

    def _validate_resp(self, resp):
        try:
            resp.raise_for_status()
        except requests.HTTPError as http_err:
            resp_str = StringIO.StringIO()
            print("%s %s" % (resp.status_code, resp.reason), file=resp_str)

            for k, v in resp.headers.items():
                if k.lower() == 'authorization':
                    v = 'REDACTED'
                print("%s: %s" % (k, v), file=resp_str)

            print(resp.content, end='', file=resp_str)

            http_err.raw_response = resp_str.getvalue()
            raise http_err

    def index(self):
        resp = requests.get("%s/api/v2/keys" % NETLOC, headers=self._headers)

        self._validate_resp(resp)

        return resp.json().get('resources')

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

        resp = requests.post("%s/api/v2/keys" % NETLOC, headers=self._headers, json=data)
        self._validate_resp(resp)
        return resp.json().get('resources')[0]

    def delete(self, key_id):
        resp = requests.delete("%s/api/v2/keys/%s" % (NETLOC, key_id), headers=self._headers)
        self._validate_resp(resp)
