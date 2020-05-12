FROM fedora:31

RUN dnf -y install golang krb5-devel && \
    go get github.com/go-delve/delve/cmd/dlv && \
    go get golang.org/x/tools/gopls@latest
