package main

import (
	"encoding/json"
	"github.com/codegangsta/martini"
	uuid2 "github.com/google/uuid"
	"github.com/kelseyhightower/envconfig"
	"github.com/martini-contrib/cors"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	// LOG TYPES
	ReqDetail = "REQUEST_DETAIL"

	// HEADER
	ReqUuid = "REQ_UUID"

	// Locator Source
	StaticFile = "STATIC_FILE"
	Eureka     = "EUREKA"
	Consul     = "CONSUL"

	// Profiles
	Dev  = "DEV"
	Test = "TEST"
	Prod = "PROD"
)

type ApplicationConfig struct {
	// StaticFile, EUREKA, CONSUL -> default => StaticFile
	LocatorSource string `envconfig:"LOCATOR_SOURCE" default:"STATIC_FILE"`
	// default => locators.json
	LocatorFilePath string `envconfig:"LOCATOR_FILE_PATH" default:"locators.json"`
	// default => 60
	TimeOut string `envconfig:"TIME_OUT" default:"60"`
	// DEV, TEST, PROD -> default => 60
	Profile string `envconfig:"PROFILE" default:"DEV"`
	// default => 4000
	Port string `envconfig:"PORT" default:"4000"`
	// default => "POST, OPTIONS, GET, PUT, DELETE"
	CorsAllowedMethods string `envconfig:"CORS_ALLOWED_METHODS" default:"POST, OPTIONS, GET, PUT, DELETE"`
	// default => Content-Type, Accept-Language, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With", Origin
	CorsAllowedHeaders string `envconfig:"CORS_ALLOWED_HEADERS" default:"Content-Type, Accept-Language, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With, Origin"`
	// default => true
	CorsAllowCredentials bool `envconfig:"CORS_ALLOW_CREDENTIALS" default:"true"`
	// default => "*"
	CorsAllowOrigins string `envconfig:"CORS_ALLOW_ORIGINS" default:"*"`
}

type Locator struct {
	Prefix string   `json:"prefix"`
	Urls   []string `json:"urls"`
}

type LocatorFile struct {
	Locators []Locator `json:"locators"`
}

var locators []Locator
var applicationConfig ApplicationConfig

func init() {
	err := envconfig.Process("", &applicationConfig)
	if err != nil {
		log.Error(err)
		panic(err)
	}

	log.SetFormatter(&log.JSONFormatter{})

	log.SetOutput(os.Stdout)
	log.SetReportCaller(true)

	if applicationConfig.Profile == Dev {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
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
	app.RunOnAddr(":" + applicationConfig.Port)
}

func corsOptions() *cors.Options {
	return &cors.Options{
		AllowMethods:     []string{applicationConfig.CorsAllowedMethods},
		AllowHeaders:     []string{applicationConfig.CorsAllowedHeaders},
		AllowCredentials: applicationConfig.CorsAllowCredentials,
		AllowOrigins:     []string{applicationConfig.CorsAllowOrigins},
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
					uuid := uuid2.New().String()

					r.URL.Path = redirectPath
					// TODO: auth işleminden sonra currentUser header ı eklenmeli
					r.Header.Add("deneme", "bilal headerrr")
					r.Header.Add(ReqUuid, uuid)
					log.WithFields(log.Fields{
						"type": ReqDetail,
					}).Info(r)
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

	timeOutInt, _ := strconv.ParseInt(applicationConfig.TimeOut, 10, 64)
	duration := time.Duration(timeOutInt * 1000 * 1000 * 1000)
	proxy.Transport = &http.Transport{
		ResponseHeaderTimeout: duration,
	}

	proxy.ErrorHandler = func(writer http.ResponseWriter, request *http.Request, err error) {
		log.Error(err)
		writer.WriteHeader(http.StatusBadGateway)
		errStr := err.Error() + " Timeout: " + applicationConfig.TimeOut + " second."
		_, _ = writer.Write([]byte(errStr))
	}

	return proxy
}

func fillLocators() {
	if applicationConfig.LocatorSource == StaticFile {
		readFile()
	} else if applicationConfig.LocatorSource == Eureka {
		// eureka
	} else if applicationConfig.LocatorSource == Consul {
		// consul
	}
}

func readFile() {
	jsonFile, err := os.Open(applicationConfig.LocatorFilePath)

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
