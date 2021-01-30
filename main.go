package main

import (
	"encoding/json"
	"github.com/codegangsta/martini"
	"github.com/martini-contrib/cors"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"
)

type Locator struct {
	Prefix string   `json:"prefix"`
	Urls   []string `json:"urls"`
}

type LocatorFile struct {
	Locators []Locator `json:"locators"`
}

var locators []Locator

func init() {
	log.SetFormatter(&log.JSONFormatter{})

	log.SetOutput(os.Stdout)
	log.SetReportCaller(true)

	// TODO: depend profile
	log.SetLevel(log.WarnLevel)
}

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

					proxy := prepareProxy(remote)

					redirectPath := getRedirectPath(splitedPath)

					r.URL.Path = redirectPath
					// TODO: auth işleminden sonra currentUser header ı eklenmeli
					r.Header.Add("deneme", "bilal")
					proxy.ServeHTTP(w, r)
				}
			}
		}
	}
}

func getRedirectPath(paths []string) string {
	redirectPath := ""
	for i, subPath := range paths {
		if i != 0 {
			redirectPath += subPath

			if i < len(paths)-1 {
				redirectPath += "/"
			}
		}
	}

	return redirectPath
}

func prepareProxy(remote *url.URL) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(remote)

	proxy.Transport = &http.Transport{
		// TODO: read environment
		ResponseHeaderTimeout: 5 * time.Second,
	}

	proxy.ErrorHandler = func(writer http.ResponseWriter, request *http.Request, err error) {
		log.Error(err)
		writer.WriteHeader(http.StatusBadGateway)
		// TODO: read environment
		errStr := err.Error() + " Timeout: 5 second."
		_, _ = writer.Write([]byte(errStr))
	}

	return proxy
}

func fillLocators() {
	// TODO: read environment
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
