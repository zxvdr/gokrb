package gokrb

/*
#cgo LDFLAGS: -lgssapi_krb5 -lkrb5 -lk5crypto -lcom_err

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gssapi/gssapi.h>
#include <gssapi/gssapi_generic.h>
#include <gssapi/gssapi_krb5.h>

typedef struct {
    gss_ctx_id_t     context;
    gss_name_t       server_name;
    long int         gss_flags;
    char*            username;
    char*            response;
} gss_client_state;

*/
import "C"

import (
	"encoding/base64"
	"errors"
	"unsafe"
)

type Context struct {
	state    *C.gss_client_state
	Response string
}

func AuthGSSClientInit(service string) (*Context, error) {
	cservice := C.CString(service)
	defer C.free(unsafe.Pointer(cservice))

	var maj_stat C.OM_uint32
	var min_stat C.OM_uint32
	var name_token C.gss_buffer_desc

	var state C.gss_client_state
	state.gss_flags = C.GSS_C_MUTUAL_FLAG | C.GSS_C_SEQUENCE_FLAG

	// Import server name first
	name_token.length = C.strlen(cservice)
	name_token.value = unsafe.Pointer(cservice)

	maj_stat = C.gss_import_name(
		&min_stat,
		&name_token,
		C.gss_krb5_nt_service_name,
		&state.server_name)

	if maj_stat != 0 {
		return nil, errors.New("Init failed")
	}

	//if C.GSS_ERROR(maj_stat) {
	//set_gss_error(maj_stat, min_stat);
	//ret = AUTH_GSS_ERROR;
	//	return nil, ErrGSS
	//}

	return &Context{state: &state}, nil
}

func (c *Context) AuthGSSClientStep(challenge string) error {
	var maj_stat C.OM_uint32
	var min_stat C.OM_uint32
	var input_token C.gss_buffer_desc
	var output_token C.gss_buffer_desc

	// Always clear out the old response
	if c.state.response != nil {
		C.free(unsafe.Pointer(c.state.response))
		c.state.response = nil
	}

	// If there is a challenge (data from the server) we need to give it to GSS
	if challenge != "" {
		value, _ := base64.StdEncoding.DecodeString(challenge)
		input_token.value = unsafe.Pointer(&value[0])
		input_token.length = (C.size_t)(len(value))
	}

	// Do GSSAPI step
	maj_stat = C.gss_init_sec_context(
		&min_stat,
		nil, // GSS_C_NO_CREDENTIAL,
		&c.state.context,
		c.state.server_name,
		nil, // GSS_C_NO_OID,
		C.OM_uint32(c.state.gss_flags),
		0,
		nil, // GSS_C_NO_CHANNEL_BINDINGS,
		&input_token,
		nil,
		&output_token,
		nil,
		nil)

	if maj_stat != C.GSS_S_COMPLETE && maj_stat != C.GSS_S_CONTINUE_NEEDED {
		return errors.New("something went wrong")
	}
	//ret = (maj_stat == GSS_S_COMPLETE) ? AUTH_GSS_COMPLETE : AUTH_GSS_CONTINUE;

	// Grab the client response to send back to the server
	if output_token.length > 0 {
		gbytes := C.GoBytes(unsafe.Pointer(output_token.value), (_Ctype_int)(output_token.length))
		c.Response = base64.StdEncoding.EncodeToString(gbytes)
		maj_stat = C.gss_release_buffer(&min_stat, &output_token)
	}
	return nil
}
