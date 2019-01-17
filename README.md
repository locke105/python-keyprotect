# python-keyprotect

[![Build Status](https://travis-ci.org/locke105/python-keyprotect.svg?branch=master)](https://travis-ci.org/locke105/python-keyprotect)
[![Apache License](http://img.shields.io/badge/license-APACHE2-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0.html)

A Python 3 client for IBM Key Protect

# Usage

```python
import os

from keyprotect import bxauth
from keyprotect.keyprotect import Keys

# env vars
api_key = os.getenv('BLUEMIX_API_KEY')
region = os.getenv('REGION')

def main():
    service_id="..."
    tokens = bxauth.auth(apikey=api_key)
    iam_token = tokens.get('access_token')
   
    kp = Keys(iamtoken=iam_token, instance_id=service_id)
    for key in kp.index():
        print("%s\t%s" % (key['id'], key['name']))

    key = kp.create(name="MyTestKey")
    print("Created key '%s'" % key['id'])

    kp.delete(key.get('id'))
    print("Deleted key '%s'" % key['id'])

    # wrap and unwrap require a non-exportable key,
    # these are also referred to as root keys
    key = kp.create(name="MyRootKey", root=True)

    # wrap/unwrap
    message = 'This is a really important message.'
    wrapped = kp.wrap(key.get('id'), message)
    ciphertext = wrapped.get("ciphertext")

    unwrapped = kp.unwrap(key.get('id'), ciphertext)
    assert message == unwrapped

    # wrap/unwrap with AAD
    message = 'This is a really important message too.'
    wrapped = kp.wrap(key.get('id'), message, aad=['python-keyprotect'])
    ciphertext = wrapped.get("ciphertext")

    unwrapped = kp.unwrap(key.get('id'), ciphertext, aad=['python-keyprotect'])
    assert message == unwrapped

if __name__ == '__main__':
    main()
```
