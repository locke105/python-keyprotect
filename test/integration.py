#!/usr/bin/env python

from __future__ import print_function

import logging
import os
import pprint
import traceback

import keyprotect
from keyprotect import bxauth


#service_id="ce46b1ab-c71f-4b1f-9fc4-4a774a49260c"
service_id = os.environ.get('KP_INSTANCE_ID')


env_vars = [os.environ.get('IBMCLOUD_API_KEY'),
            os.environ.get('BLUEMIX_API_KEY')]


# iterate throuh in order and use first one that is not nil/empty
for var in env_vars:
    if var:
        apikey = var
        break


def get_client(region):
    tm = bxauth.TokenManager(api_key=apikey)

    return keyprotect.Keys(
        iamtoken=tm.get_token(),
        region=region,
        instance_id=service_id
    )


def main():
    kp = get_client(region="us-east")

    for key in kp.index():
        print("%s\t%s" % (key['id'], key['name']))

    key = kp.create(name="MyTestKey")
    print("Created key '%s'" % key['id'])

    print(kp.get(key.get('id')))

    kp.delete(key.get('id'))
    print("Deleted key '%s'" % key['id'])

    # wrap/unwrap
    print("Creating root key")
    key = kp.create(name="MyRootKey", root=True)

    message = b'This is a really important message.'
    print("Wrapping message: %r" % message)
    wrapped = kp.wrap(key.get('id'), message)
    ciphertext = wrapped.get("ciphertext")

    print("Unwrapping message...")
    unwrapped = kp.unwrap(key.get('id'), ciphertext)
    print("Unwrapped plaintext: %r" % unwrapped)
    assert message == unwrapped

    kp.delete(key.get('id'))
    print("Deleted key '%s'" % key['id'])

    # wrap/unwrap with AAD
    print("Creating root key")
    key = kp.create(name="MyRootKey", root=True)

    message = b'This is a really important message too.'
    print("Wrapping message: %r" % message)
    wrapped = kp.wrap(key.get('id'), message, aad=['python-keyprotect'])
    ciphertext = wrapped.get("ciphertext")

    print("Unwrapping message...")
    unwrapped = kp.unwrap(key.get('id'), ciphertext, aad=['python-keyprotect'])
    print("Unwrapped plaintext: %r" % unwrapped)
    assert message == unwrapped

    kp.delete(key.get('id'))
    print("Deleted key '%s'" % key['id'])


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    try:
        main()
    except Exception as ex:
        traceback.print_exc()
        if hasattr(ex, "raw_response"):
            print(ex.raw_response)
