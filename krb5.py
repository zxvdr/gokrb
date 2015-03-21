#!/usr/bin/env python

import kerberos

service = "HTTP@el7.example.com"
__, krb_context = kerberos.authGSSClientInit(service)
kerberos.authGSSClientStep(krb_context, "")

resp = kerberos.authGSSClientResponse(krb_context)
print(resp)
