package main

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"os"

	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/service"
	"github.com/jcmturner/gokrb5/v8/spnego"
)

func dumpRequest(r *http.Request) {
	requestDump, err := httputil.DumpRequest(r, true)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(requestDump))
}

func hello(w http.ResponseWriter, r *http.Request) {
	dumpRequest(r)
	_, _ = fmt.Fprintf(w, "Hello, you are not authenticated.\n")
}

func krb5hello(w http.ResponseWriter, r *http.Request) {
	dumpRequest(r)
	_, _ = fmt.Fprintf(w, "Hello, you used Kerberos authentication.\n")
}

func main() {
	_, err := config.Load("/krb5/krb5.conf")
	if err != nil {
		panic(err)
	}
	kt, err := keytab.Load("/krb5/web/run/keytab")
	if err != nil {
		panic(err)
	}
	js, _ := kt.JSON()
	fmt.Println("keytab: ", js)

	l := log.New(os.Stderr, "GOKRB5 Service: ", log.Ldate|log.Ltime|log.Lshortfile)
	srv := service.Logger(l)
	srvName := service.SName("HTTP/web.local")

	http.HandleFunc("/hello", hello)
	h := http.HandlerFunc(krb5hello)
	http.Handle("/krb5hello", spnego.SPNEGOKRB5Authenticate(h, kt, srvName, srv))

	fmt.Println("Running server")
	_ = http.ListenAndServe(":80", nil)
}
