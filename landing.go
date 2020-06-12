package main

import "net/http"

var landingTmpl = []byte(`
<!doctype html>
<html>
</html>
`)

func handleLanding(reqID string, rw http.ResponseWriter, r *http.Request) {
	rw.Header().Set("Content-Tyle", "text/html")
	rw.WriteHeader(200)
	rw.Write(landingTmpl)
}
