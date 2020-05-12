package main

// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
// #include <gssapi/gssapi.h>
import "C"
import (
	"encoding/base64"
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

func loadCredentials() C.gss_cred_id_t {
       // TODO: load keytab into cred_id_t
}

func handle(w http.ResponseWriter, r *http.Request) {
	dumpRequest(r)
	auth := r.Header.Get("Authorization")
	if auth == "" {
		w.Header().Set("WWW-Authenticate", "Negotiate")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// The server will decode the gssapi-data and pass this to the SPNEGO
	// GSSAPI mechanism in the gss_accept_security_context function.  If the
	// context is not complete, the server will respond with a 401 status
	// code with a WWW-Authenticate header containing the gssapi-data.

	// 10: because that's the length of 'Negotiate '
	fmt.Println("Header base64:", auth[10:])
	inputToken, err := base64.StdEncoding.DecodeString(auth[10:])
	if err != nil {
		fmt.Printf("Error decoding string: %s ", err.Error())
	}
	fmt.Println("Header: ", string(inputToken))

	var contextHdl C.gss_ctx_id_t = C.GSS_C_NO_CONTEXT
	var minStat C.OM_uint32

	majStat := C.gss_accept_sec_context(&minStat,
		&contextHdl,    // If I don't need to keep the context for further calls, this should be fine
		cred_hdl,       // I think I need to load keytab here somehow
		input_token,    // This is what I've got from the client
		input_bindings, // No idea yet
		&client_name,   // No idea yet
		&mech_type,     // No idea yet
		output_token,   // No idea yet
		&ret_flags,     // No idea yet
		&time_rec,      // No idea yet
		&deleg_cred)    // No idea yet

	io.WriteString(w, "aaabbb")
}

func main() {
	portNumber := "9000"
	http.HandleFunc("/", handle)
	fmt.Println("Server listening on port ", portNumber)
	http.ListenAndServe(":"+portNumber, nil)
}
