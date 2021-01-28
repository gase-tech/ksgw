package main

import (
	"github.com/codegangsta/martini"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

type Locator struct {
	prefix string
	urls   []string
}

var locators []*Locator

func main() {
	locators = append(locators, &Locator{
		prefix: "go-service",
		urls:   []string{"http://localhost:8085"},
	})

	locators = append(locators, &Locator{
		prefix: "user-service",
		urls:   []string{"http://localhost:9075"},
	})

	app := martini.Classic()
	app.Post("/**", handler())
	app.Get("/**", handler())
	app.Put("/**", handler())
	app.Delete("/**", handler())
	app.Options("/**", handler())
	app.RunOnAddr(":4000")
}

func handler() func(http.ResponseWriter, *http.Request, martini.Params) {
	return func(w http.ResponseWriter, r *http.Request, params martini.Params) {
		path := params["_1"]
		splitedPath := strings.Split(path, "/")
		if len(splitedPath) > 0 {
			reqPrefix := splitedPath[0]

			for _, locator := range locators {
				if locator.prefix == reqPrefix {
					remote, err := url.Parse(locator.urls[0])
					if err != nil {
						panic(err)
					}
					proxy := httputil.NewSingleHostReverseProxy(remote)

					redirectPath := ""
					for i, subPath := range splitedPath {
						if i != 0 {
							redirectPath += subPath

							if i < len(splitedPath)-1 {
								redirectPath += "/"
							}
						}
					}

					r.URL.Path = redirectPath
					proxy.ServeHTTP(w, r)
				}
			}
		}
	}
}
