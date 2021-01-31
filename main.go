package main

import (
	"encoding/json"
	"github.com/carlescere/scheduler"
	"github.com/codegangsta/martini"
	"github.com/go-resty/resty/v2"
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
	Scheduler = "SCHEDULER"

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

	// Languages
	EN = "EN"
	TR = "TR"

	// Messages
	ServiceNotFound           = "ServiceNotFound"
	SuccessfullyFetchOnFile   = "SuccessfullyFetchOnFile"
	SuccessfullyFetchOnEureka = "SuccessfullyFetchOnEureka"
	GenericError              = "GenericError"
)

type ApplicationConfig struct {
	// EN, TR
	Language string `envconfig:"LANGUAGE" default:"EN"`
	// StaticFile, EUREKA, CONSUL -> default => StaticFile
	LocatorSource string `envconfig:"LOCATOR_SOURCE" default:"STATIC_FILE"`
	// default => locators.json
	LocatorFilePath string `envconfig:"LOCATOR_FILE_PATH" default:"locators.json"`
	// default => 30 second
	FetchLocatorsSecond int `envconfig:"FETCH_LOCATORS_SECOND" default:"30"`
	// default => http://localhost:8090/eureka/apps
	EurekaUrl string `envconfig:"EUREKA_URL" default:"http://localhost:8090/eureka/apps"`
	// default => ""
	EurekaUsername string `envconfig:"EUREKA_USERNAME"`
	// default => ""
	EurekaPassword string `envconfig:"EUREKA_PASSWORD"`
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
var client = resty.New()
var i18n map[string]string

func init() {
	err := envconfig.Process("", &applicationConfig)
	if err != nil {
		log.Error(err)
		panic(err)
	}

	loggingConfiguration()

	i18nConfiguration()
}

func i18nConfiguration() {
	var jsonFile *os.File
	var err error
	if applicationConfig.Language == EN {
		jsonFile, err = os.Open("EN.json")
	} else if applicationConfig.Language == TR {
		jsonFile, err = os.Open("TR.json")
	} else {
		jsonFile, err = os.Open("EN.json")
	}

	if err != nil {
		panic(err)
	}

	defer jsonFile.Close()
	byteValue, _ := ioutil.ReadAll(jsonFile)
	err = json.Unmarshal(byteValue, &i18n)

	if err != nil {
		panic(err)
	}
}

func loggingConfiguration() {
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

			var equivalentLocator *Locator
			for _, locator := range locators {
				if locator.Prefix == reqPrefix {
					equivalentLocator = &locator
					break
				}
			}

			if equivalentLocator != nil {
				remote, err := url.Parse(equivalentLocator.Urls[0])
				if err != nil {
					log.WithFields(log.Fields{
						"type": ReqDetail,
					}).Error(err)
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
			} else {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write(generateGenericErrorJsonStr(i18n[ServiceNotFound]))
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
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusBadGateway)
		errStr := err.Error() + " Timeout: " + applicationConfig.TimeOut + " second."
		_, _ = writer.Write(generateGenericErrorJsonStr(errStr))
	}

	return proxy
}

func fillLocators() {
	var receiveLocatorStrategy func()
	if applicationConfig.LocatorSource == StaticFile {
		receiveLocatorStrategy = func() { receiveLocatorsOnFile() }
	} else if applicationConfig.LocatorSource == Eureka {
		receiveLocatorStrategy = func() { receiveLocatorsOnEureka() }
	} else if applicationConfig.LocatorSource == Consul {
		// consul
	}

	_, _ = scheduler.Every(applicationConfig.FetchLocatorsSecond).Seconds().Run(receiveLocatorStrategy)
}

func receiveLocatorsOnEureka() {
	request := client.R()
	request.SetHeader("Content-Type", "application/json")
	request.SetHeader("Accept", "application/json")
	request.SetResult(&EurekaRegisteredServiceInfos{})

	if applicationConfig.EurekaUsername != "" && applicationConfig.EurekaPassword != "" {
		request.SetBasicAuth(applicationConfig.EurekaUsername, applicationConfig.EurekaPassword)
	}

	response, err := request.Get(applicationConfig.EurekaUrl)

	if err != nil {
		log.WithFields(log.Fields{
			"type": Scheduler,
		}).Error(err)
	}

	result := response.Result().(*EurekaRegisteredServiceInfos)

	locators = make([]Locator, len(result.Application.Apps))
	for i, service := range result.Application.Apps {
		locator := &Locator{}
		lower := strings.ToLower(service.Name)
		locator.Prefix = lower

		urls := make([]string, len(service.Instances))
		for i, instance := range service.Instances {
			urls[i] = "http://" + instance.Hostname + ":" + strconv.FormatInt(int64(instance.Port.Value), 10)
		}
		locator.Urls = urls
		locators[i] = *locator
	}
	log.WithFields(log.Fields{
		"type": Scheduler,
	}).Debugf(i18n[SuccessfullyFetchOnEureka])
}

func receiveLocatorsOnFile() {
	jsonFile, err := os.Open(applicationConfig.LocatorFilePath)

	if err != nil {
		log.WithFields(log.Fields{
			"type": Scheduler,
		}).Error(err)
	}

	defer jsonFile.Close()
	byteValue, _ := ioutil.ReadAll(jsonFile)

	var fileObj LocatorFile
	err = json.Unmarshal(byteValue, &fileObj)

	if err != nil {
		panic(err)
	}

	locators = fileObj.Locators
	log.WithFields(log.Fields{
		"type": Scheduler,
	}).Debugf(i18n[SuccessfullyFetchOnFile])
}

type EurekaRegisteredServiceInfos struct {
	Application EurekaRegisteredApp `json:"applications"`
}

type EurekaRegisteredApp struct {
	Version string                      `json:"versions__delta"`
	Hash    string                      `json:"apps__hashcode"`
	Apps    []EurekaRegistryApplication `json:"application"`
}

type EurekaRegistryApplication struct {
	Name      string                   `json:"name"`
	Instances []EurekaRegistryInstance `json:"instance"`
}

type EurekaRegistryInstance struct {
	InstanceId       string             `json:"instanceId"`
	Hostname         string             `json:"hostname"`
	App              string             `json:"app"`
	IpAddress        string             `json:"ipAddr"`
	Status           string             `json:"status"`
	OverriddenStatus string             `json:"overriddenStatus"`
	Port             EurekaRegisterInfo `json:"port"`
	SecurePort       EurekaRegisterInfo `json:"securePort"`
	CountryId        int                `json:"countryId"`
}

type EurekaRegisterInfo struct {
	Value    int    `json:"$"`
	IsActive string `json:"@enabled"`
}

func generateGenericErrorJsonStr(msg string) []byte {
	model := GenericErrorModel{Msg: msg}

	jsStr, err := json.Marshal(model)

	if err != nil {
		log.Error(err)
		return []byte(i18n[GenericError])
	}

	return jsStr
}

type GenericErrorModel struct {
	Msg string `json:"msg"`
}
