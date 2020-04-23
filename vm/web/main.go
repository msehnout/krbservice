package main

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"

	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/julienschmidt/httprouter"
)

func dumpRequest(r *http.Request) {
	requestDump, err := httputil.DumpRequest(r, true)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(requestDump))
}

func Index(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	dumpRequest(r)
	_, _ = fmt.Fprintf(w, "Hello, you are authenticated.\n")
}

func Hello(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	dumpRequest(r)
	_, _ = fmt.Fprintf(w, "Hello, you are authenticated and this is the name: %s.\n", params.ByName("name"))
}

type API struct {
	keytab *keytab.Keytab
	router *httprouter.Router
}

func (api *API) Serve(listener net.Listener) error {
	server := http.Server{Handler: api}

	err := server.Serve(listener)
	if err != nil && err != http.ErrServerClosed {
		return err
	}

	return nil
}

// ServeHTTP logs the request, sets content-type, and forwards the request to appropriate handler
func (api *API) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	handler := spnego.SPNEGOKRB5Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		api.router.ServeHTTP(writer, request)
	}), api.keytab)
	handler.ServeHTTP(writer, request)
}

func main() {
	kt, err := keytab.Load("/tmp/keytab")
	if err != nil {
		panic(err)
	}
	js, _ := kt.JSON()
	fmt.Println("keytab: ", js)

	router := httprouter.New()
	router.GET("/", Index)
	router.GET("/hello/:name", Hello)

	api := API{
		keytab: kt,
		router: router,
	}

	ln, err := net.Listen("tcp", ":80")
	if err != nil {
		panic(err)
	}
	_ = api.Serve(ln)
}
