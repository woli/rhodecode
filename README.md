rhodecode
=========

A go package that can be used to access the RhodeCode API

$ go get github.com/woli/rhodecode

#### Usage example:

    package main

    import (
            "fmt"
            "github.com/woli/rhodecode"
    )

    func main() {
            // necessary if using https
            rhodecode.SetCertAuth([]byte("<cert>"))

            r := rhodecode.New("<url>", "<apiKey>")
            if repos, err := r.GetRepos("1"); err != nil {
                    fmt.Println(err)
            } else {
                    for i := range repos {
                            fmt.Printf("%+v\n", repos[i])
                    }
            }
    }
