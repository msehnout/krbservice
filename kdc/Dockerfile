FROM fedora:31

RUN dnf -y install krb5-server

ENV KRB5_CONFIG /krb5/krb5.conf
ENV KRB5_KDC_PROFILE /krb5/kdc.conf

CMD bash /krb5/init-kdc.sh
