package main

// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
// char* helper(void *i) { return (char*)i; }
import "C"
import "unsafe"

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
)

func dumpRequest(r *http.Request) {
	requestDump, err := httputil.DumpRequest(r, true)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(requestDump))
}

func handle(w http.ResponseWriter, r *http.Request) {
	dumpRequest(r)
	auth := r.Header.Get("Authorization")
	if auth == "" {
		w.Header().Set("WWW-Authenticate", "Negotiate")
		w.WriteHeader(http.StatusUnauthorized)
	}

	a := "aaa"
	b := "bbb"
	ca := C.CString(a)
	defer C.free(unsafe.Pointer(ca))
	cb := C.CString(b)
	defer C.free(unsafe.Pointer(cb))
	buf := C.helper(C.malloc(C.size_t(10)))
	C.strcat(buf, ca)
	C.strcat(buf, cb)
	res := C.GoString(buf)

	io.WriteString(w, res)
}

func main() {
	portNumber := "9000"
	http.HandleFunc("/", handle)
	fmt.Println("Server listening on port ", portNumber)
	http.ListenAndServe(":"+portNumber, nil)
}

