package main

/*
#cgo LDFLAGS: -lgssapi_krb5
#include <stdlib.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>

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
	"io/ioutil"
	"log"
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

func byteArrayToGssBuffer(buffer []byte) C.gss_buffer_t {
	return C.GssBufferTypeFromVoidPtr(unsafe.Pointer(&buffer), (C.size_t)(len(buffer)))
}

func loadCredentials(filename string) C.gss_cred_id_t {
	// https://web.mit.edu/kerberos/krb5-devel/doc/appdev/gssapi.html#importing-and-exporting-credentials
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}

	var majStat C.OM_uint32
	var minStat C.OM_uint32
	var inputToken C.gss_buffer_t = byteArrayToGssBuffer(content)
	var credHandle C.gss_cred_id_t

	majStat = C.gss_import_cred(&minStat, inputToken, &credHandle)

	log.Println("Major status:", majStat)
	log.Println("Minor status:", minStat)

	return credHandle
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
	// log.Println("Header base64:", auth[10:])
	// TODO: use something better then 10:
	inputTokenBase64 := []byte(auth[10:])
	var inputTokenBytes []byte = make([]byte, 4096)
	log.Println("Decoding header")
	_, err := base64.StdEncoding.Decode(inputTokenBytes, inputTokenBase64)
	if err != nil {
		log.Printf("Error decoding input token: %s ", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var minStat C.OM_uint32
	var contextHdl C.gss_ctx_id_t = C.GSS_C_NO_CONTEXT
	log.Println("Loading credentials")
	var credHdl C.gss_cred_id_t = loadCredentials("/tmp/keytab")
	log.Println("Converting input token")
	var inputToken C.gss_buffer_t = byteArrayToGssBuffer(inputTokenBytes)
	var outputToken C.gss_buffer_t
	var retFlags C.uint = 0

	log.Println("Calling gss accept sec context")
	// https://tools.ietf.org/html/rfc2744.html#section-5.1
	majStat := C.gss_accept_sec_context(&minStat,
		&contextHdl,                 // If I don't need to keep the context for further calls, this should be fine
		credHdl,                     // I think I need to load keytab here somehow
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

	log.Println("Major status:", majStat)
	log.Println("Minor status:", minStat)

	C.FreeGssBufferType(inputToken)

	io.WriteString(w, "aaabbb")
}

func main() {
	portNumber := "9000"
	http.HandleFunc("/", handle)
	log.Println("Server listening on port ", portNumber)
	http.ListenAndServe(":"+portNumber, nil)
}
