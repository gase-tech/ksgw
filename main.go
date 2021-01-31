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
		receiveLocatorStrategy = func() { receiveLocatorsOnConsul() }
	}

	_, _ = scheduler.Every(applicationConfig.FetchLocatorsSecond).Seconds().Run(receiveLocatorStrategy)
}

func receiveLocatorsOnConsul() {
	checkResult := getConsulChecks()

	if checkResult != nil {
		healthyServices := filterConsulServices(*checkResult, func(serviceCheck ConsulChecksResponse) bool {
			if serviceCheck.Status != Passing {
				return false
			} else {
				return true
			}
		})

		if len(healthyServices) > 0 {
			groupedServices := groupConsulChecksByServiceName(healthyServices)
			locators = nil

			for service, instances := range groupedServices {
				locator := &Locator{}
				lower := strings.ToLower(service)
				locator.Prefix = lower

				urls := make([]string, len(instances))
				for i, instance := range instances {
					detail := getConsulServiceDetail(instance.ServiceID)
					urls[i] = "http://" + detail.Address + ":" + strconv.FormatInt(int64(detail.Port), 10)
				}
				locator.Urls = urls
				locators = append(locators, *locator)
			}

			log.WithFields(log.Fields{
				"type": Scheduler,
			}).Debugf(i18n[SuccessfullyFetchOnConsul])
		}
	}
}

func getConsulServiceDetail(serviceID string) *ConsulServiceInfo {
	request := client.R()

	request.SetHeader("Content-Type", "application/json")
	request.SetHeader("Accept", "application/json")
	request.SetResult(&ConsulServiceInfo{})

	if applicationConfig.ConsulUsername != "" && applicationConfig.ConsulPassword != "" {
		request.SetBasicAuth(applicationConfig.ConsulPassword, applicationConfig.ConsulPassword)
	}

	serviceInfoUrl := applicationConfig.ConsulUrl + "/agent/service/" + serviceID
	infoResp, err := request.Get(serviceInfoUrl)

	if err != nil {
		log.WithFields(log.Fields{
			"type": Scheduler,
		}).Error(err)
		return nil
	}

	return infoResp.Result().(*ConsulServiceInfo)
}

func groupConsulChecksByServiceName(services []ConsulChecksResponse) map[string][]ConsulChecksResponse {
	result := make(map[string][]ConsulChecksResponse)

	for _, service := range services {
		result[service.ServiceName] = append(result[service.ServiceName], service)
	}

	return result
}

func getConsulChecks() *[]ConsulChecksResponse {
	request := client.R()

	request.SetHeader("Content-Type", "application/json")
	request.SetHeader("Accept", "application/json")
	request.SetResult(&map[string]*ConsulChecksResponse{})

	if applicationConfig.ConsulUsername != "" && applicationConfig.ConsulPassword != "" {
		request.SetBasicAuth(applicationConfig.ConsulPassword, applicationConfig.ConsulPassword)
	}

	checkUrl := applicationConfig.ConsulUrl + "/agent/checks"
	checkResponse, err := request.Get(checkUrl)

	if err != nil {
		log.WithFields(log.Fields{
			"type": Scheduler,
		}).Error(err)
		return nil
	}

	result := checkResponse.Result().(*map[string]*ConsulChecksResponse)

	var checkList []ConsulChecksResponse

	for _, v := range *result {
		checkList = append(checkList, *v)
	}

	return &checkList
}

func filterConsulServices(sources []ConsulChecksResponse, criteria func(serviceCheck ConsulChecksResponse) bool) []ConsulChecksResponse {
	var result []ConsulChecksResponse
	for _, source := range sources {
		if criteria(source) {
			result = append(result, source)
		}
	}
	return result
}

func receiveLocatorsOnEureka() {
	result := getEurekaServices()

	if result != nil {
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
}

func getEurekaServices() *EurekaRegisteredServiceInfos {
	request := client.R()
	request.SetHeader("Content-Type", "application/json")
	request.SetHeader("Accept", "application/json")
	request.SetResult(&EurekaRegisteredServiceInfos{})

	if applicationConfig.EurekaUsername != "" && applicationConfig.EurekaPassword != "" {
		request.SetBasicAuth(applicationConfig.EurekaUsername, applicationConfig.EurekaPassword)
	}
	eurekaUrl := applicationConfig.EurekaUrl + "/eureka/apps"
	response, err := request.Get(eurekaUrl)

	if err != nil {
		log.WithFields(log.Fields{
			"type": Scheduler,
		}).Error(err)
		return nil
	}

	return response.Result().(*EurekaRegisteredServiceInfos)
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

func generateGenericErrorJsonStr(msg string) []byte {
	model := GenericErrorModel{Msg: msg}

	jsStr, err := json.Marshal(model)

	if err != nil {
		log.Error(err)
		return []byte(i18n[GenericError])
	}

	return jsStr
}
