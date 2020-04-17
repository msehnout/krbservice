FROM fedora:31

RUN dnf -y install krb5-workstation

#CMD /bin/bash -c 'cp /krb5/krb5.conf /etc/krb5.conf; while touch /dev/null; do sleep 1; done'
CMD /bin/bash -c 'cp /krb5/krb5.conf /etc/krb5.conf; tail -f /dev/null'
