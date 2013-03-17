rhodecode
=========

A go package that can be used to access the RhodeCode API (v1.5.3)

$ go get github.com/woli/rhodecode

#### Usage example:

	package main

	import (
		"fmt"
		"github.com/woli/rhodecode"
		"net/http"
	)

	func main() {
		s, _ := rhodecode.New("<baseurl>", "<apikey>", http.DefaultClient)

		r, err := s.Repos.List().Do(1)
		if err != nil {
			panic(err)
		} else {
			for _, repo := range r.Repos {
				fmt.Printf("%+v\n", repo)
			}
		}
	}