package main

import (
	"encoding/json"
	"github.com/codegangsta/martini"
	"github.com/martini-contrib/cors"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
)

type Locator struct {
	Prefix string   `json:"prefix"`
	Urls   []string `json:"urls"`
}

type LocatorFile struct {
	Locators []Locator `json:"locators"`
}

var locators []Locator

func main() {
	fillLocators()
	prepareAndStartServer()
}

func prepareAndStartServer() {
	app := martini.Classic()
	app.Use(cors.Allow(corsOptions()))
	app.Post("/**", genericHandler())
	app.Get("/**", genericHandler())
	app.Put("/**", genericHandler())
	app.Delete("/**", genericHandler())
	app.Options("/**", genericHandler())
	app.RunOnAddr(":4000")
}

func corsOptions() *cors.Options {
	return &cors.Options{
		AllowMethods:     []string{"POST, OPTIONS, GET, PUT, DELETE"},
		AllowHeaders:     []string{"Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With", "Origin"},
		AllowCredentials: true,
		AllowAllOrigins:  true,
	}
}

func genericHandler() func(http.ResponseWriter, *http.Request, martini.Params) {
	return func(w http.ResponseWriter, r *http.Request, params martini.Params) {
		path := params["_1"]
		splitedPath := strings.Split(path, "/")
		if len(splitedPath) > 0 {
			reqPrefix := splitedPath[0]

			for _, locator := range locators {
				if locator.Prefix == reqPrefix {
					remote, err := url.Parse(locator.Urls[0])
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
					// TODO: auth işleminden sonra currentUser header ı eklenmeli
					r.Header.Add("deneme", "bilal")
					proxy.ServeHTTP(w, r)
				}
			}
		}
	}
}

func fillLocators() {
	readFile()
}

func readFile() {
	jsonFile, err := os.Open("locators.json")

	if err != nil {
		panic(err)
	}

	defer jsonFile.Close()
	byteValue, _ := ioutil.ReadAll(jsonFile)

	var fileObj LocatorFile
	err = json.Unmarshal(byteValue, &fileObj)

	if err != nil {
		panic(err)
	}

	locators = fileObj.Locators
}
