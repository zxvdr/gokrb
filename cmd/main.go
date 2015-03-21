package main

import (
	"fmt"
	"github.com/zxvdr/gokrb"
	"net/http"
	"net/http/httputil"
)

func main() {
	client := &http.Client{}

	req, err := http.NewRequest("GET", "http://el7/", nil)
	if err != nil {
		panic(err)
	}
	krb, err := gokrb.AuthGSSClientInit("HTTP@el7.example.com")
	if err != nil {
		panic(err)
	}
	err = krb.AuthGSSClientStep("")
	if err != nil {
		panic(err)
	}
	fmt.Printf("Authorization: %s\n", krb.Response)
	req.Header.Add("Authorization", "Negotiate "+krb.Response)
	dump, err := httputil.DumpRequest(req, true)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s\n", dump)

	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	dump, err = httputil.DumpResponse(resp, true)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s\n", dump)
}
