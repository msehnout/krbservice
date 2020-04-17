#!/bin/bash

# This file serves as a "first-and-the-only-boot" configuration
# file, because these commands cannot run during the image build
# phase in Dockerfile.

set -e

whoami

kdb5_util -r LOCAL destroy -f || touch /dev/null
kdb5_util create -r LOCAL -P password
kadmin.local -r LOCAL add_principal -pw password admin/admin@LOCAL
kadmin.local -r LOCAL add_principal -pw password user@LOCAL
kadmin.local -r LOCAL add_principal -pw password HTTP/web.local@LOCAL
kadmin.local -r LOCAL ktadd -k /krb5/web/run/keytab HTTP/web.local@LOCAL

kdb5_util -r LOCAL dump -verbose /tmp/dumpfile
krb5kdc
tail -f /var/log/krb5kdc.log
