package main

import (
	"net/url"
)

func ProfileFor(email string) string {
	return url.Values{
		"email": {email},
		"role":  {"user"},
	}.Encode()
}

func main() {
}
