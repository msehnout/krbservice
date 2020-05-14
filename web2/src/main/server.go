package main

/*
#cgo LDFLAGS: -lgssapi_krb5
#include <stdlib.h>
#include <gssapi/gssapi.h>

gss_buffer_t GssBufferTypeFromVoidPtr(void *buffer, size_t length) {
	// https://tools.ietf.org/html/rfc2744.html#section-3.2
	gss_buffer_t ptr = (gss_buffer_t)malloc(sizeof(gss_buffer_desc));
	ptr->length = length;
	ptr->value = buffer;
	return ptr;
}

void FreeGssBufferType(gss_buffer_t buffer) {
	free(buffer);
}
*/
import "C"

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"unsafe"
)

/*

# TODO:
 * Function to load the keytab into cred_id_t
 * Handle return values from call to gss_accept_sec_context
 * Load the library dynamically? Isn't it possible to let the linker do this for me?
 * Use something better than 10:
*/

func dumpRequest(r *http.Request) {
	requestDump, err := httputil.DumpRequest(r, true)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(requestDump))
}

/*
func loadCredentials() C.gss_cred_id_t {
	// TODO: load keytab into cred_id_t
}
*/

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
	// TODO: use something better then 10:
	inputTokenBase64 := []byte(auth[10:])
	var inputTokenBytes []byte
	n, err := base64.StdEncoding.Decode(inputTokenBytes, inputTokenBase64)
	if err != nil {
		fmt.Printf("Error decoding input token: %s ", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var contextHdl C.gss_ctx_id_t = C.GSS_C_NO_CONTEXT
	var minStat C.OM_uint32
	var inputToken C.gss_buffer_t = C.GssBufferTypeFromVoidPtr(unsafe.Pointer(&inputTokenBytes), (C.size_t)(len(inputTokenBytes)))
	var outputToken C.gss_buffer_t
	var retFlags C.uint = 0

	// https://tools.ietf.org/html/rfc2744.html#section-5.1
	majStat := C.gss_accept_sec_context(&minStat,
		&contextHdl,                 // If I don't need to keep the context for further calls, this should be fine
		cred_hdl,                    // I think I need to load keytab here somehow
		inputToken,                  // This is what I've got from the client
		C.GSS_C_NO_CHANNEL_BINDINGS, // input_chan_bindings
		(*C.gss_name_t)(C.NULL),     // src_name
		(*C.gss_OID)(C.NULL),        // mech_type
		// token to be passed back to the caller, but since I don't implement support for keeping the context,
		// I cannot handle it. Needs to be released with call to gss_release_buffer()
		outputToken,
		(*C.uint)(&retFlags),       // ret_flags, allows for further configuration
		(*C.uint)(C.NULL),          // time_rec
		(*C.gss_cred_id_t)(C.NULL)) // delegated_cred_handle

	io.WriteString(w, "aaabbb")
}

func main() {
	portNumber := "9000"
	http.HandleFunc("/", handle)
	fmt.Println("Server listening on port ", portNumber)
	http.ListenAndServe(":"+portNumber, nil)
}
