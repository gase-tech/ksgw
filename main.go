package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/carlescere/scheduler"
	"github.com/codegangsta/martini"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-resty/resty/v2"
	uuid2 "github.com/google/uuid"
	token_validation "github.com/imminoglobulib/ksgw/token-validation"
	"github.com/kelseyhightower/envconfig"
	"github.com/martini-contrib/cors"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

var locators []Locator
var appCfg ApplicationConfig
var client = resty.New()
var i18n map[string]string
var securityRules []SecurityRule

func init() {
	err := envconfig.Process("", &appCfg)
	if err != nil {
		log.WithFields(log.Fields{"type": Config}).Error(err)
		panic(err)
	}

	loggingConfiguration()

	i18nConfiguration()

	securityConfiguration()
}

func securityConfiguration() {
	if appCfg.SecurityEnabled {
		securityConfigUpdater := func() { fillSecurityRulesFromFile() }

		_, _ = scheduler.Every(appCfg.FetchSecuritySecond).Seconds().Run(securityConfigUpdater)
	}
}

func fillSecurityRulesFromFile() {
	yamlFile, err := os.Open(appCfg.SecurityYamlPath)

	if err != nil {
		log.WithFields(log.Fields{"type": Config}).Error(err)
	}

	defer yamlFile.Close()
	byteValue, _ := ioutil.ReadAll(yamlFile)

	var fileObj SecurityYaml
	err = yaml.Unmarshal(byteValue, &fileObj)

	if err != nil {
		log.WithFields(log.Fields{"type": Config}).Error(err)
	}

	securityRules = fileObj.Rules
	log.WithFields(log.Fields{"type": Config}).Debugf(i18n[SecurityConfigUpdated])
}

func i18nConfiguration() {
	var jsonFile *os.File
	var err error
	if appCfg.Language == EN {
		jsonFile, err = os.Open("i18n/EN.json")
	} else if appCfg.Language == TR {
		jsonFile, err = os.Open("i18n/TR.json")
	} else {
		err := errors.New("Unsupported Language.")
		log.WithFields(log.Fields{"type": Config}).Error(err)
		panic(err)
	}

	if err != nil {
		log.WithFields(log.Fields{"type": Config}).Error(err)
		panic(err)
	}

	defer jsonFile.Close()
	byteValue, _ := ioutil.ReadAll(jsonFile)
	err = json.Unmarshal(byteValue, &i18n)

	if err != nil {
		log.WithFields(log.Fields{"type": Config}).Error(err)
		panic(err)
	}
}

func loggingConfiguration() {
	log.SetFormatter(&log.JSONFormatter{})

	log.SetOutput(os.Stdout)
	log.SetReportCaller(true)

	if appCfg.Profile == Dev {
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
	app.Use(requestMarker)
	app.Post("/**", securityHandler(), genericHandler())
	app.Get("/**", securityHandler(), genericHandler())
	app.Put("/**", securityHandler(), genericHandler())
	app.Delete("/**", securityHandler(), genericHandler())
	app.Options("/**", securityHandler(), genericHandler())
	app.RunOnAddr(":" + appCfg.Port)
}

func corsOptions() *cors.Options {
	return &cors.Options{
		AllowMethods:     []string{appCfg.CorsAllowedMethods},
		AllowHeaders:     []string{appCfg.CorsAllowedHeaders},
		AllowCredentials: appCfg.CorsAllowCredentials,
		AllowOrigins:     []string{appCfg.CorsAllowOrigins},
	}
}

func requestMarker(_ http.ResponseWriter, req *http.Request) {
	uuid := uuid2.New().String()
	req.Header.Add(ReqUuid, uuid)
}

func securityHandler() func(http.ResponseWriter, *http.Request, martini.Params) {
	return func(w http.ResponseWriter, r *http.Request, params martini.Params) {
		if appCfg.SecurityEnabled {
			rule := findSuitableSecurityRule(*r)

			if rule != nil {
				authToken := r.Header.Get(Authorization)

				userID, authenticated, authorized, err := tokenValidation(authToken, rule.Roles)

				if err != nil {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusInternalServerError)
					_, _ = w.Write(generateGenericErrorJsonStr(err.Error()))
					return
				}

				if !authenticated {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusUnauthorized)
					_, _ = w.Write(generateGenericErrorJsonStr(i18n[RequireAuthentication]))
					return
				}

				if !authorized {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusForbidden)
					_, _ = w.Write(generateGenericErrorJsonStr(i18n[RequireAuthorization]))
					return
				}

				r.Header.Add(appCfg.CurrentUserIdHeaderKey, userID)
			}
		}
	}
}

//tokenValidation return: userId, authenticated, authorized, error
func tokenValidation(token string, expectedRoles []string) (string, bool, bool, error) {
	log.WithFields(log.Fields{"type": Security}).Debugf("Token : %v \nExpected Roles: %v", token, expectedRoles)
	if token == "" || !strings.HasPrefix(token, SupportedTokenType) {
		return "", false, false, errors.New(i18n[InvalidTokenSyntax])
	} else {
		var userId string
		var userRoles []string
		var err error
		if appCfg.TokenValidationStrategy == Grpc {
			userId, userRoles, err = callGrpcTokenValidationService(removeTypeInToken(token))
		} else if appCfg.TokenValidationStrategy == Rest {
			userId, userRoles, err = callRestTokenValidationService(removeTypeInToken(token))
		} else if appCfg.TokenValidationStrategy == Static {
			userId, userRoles, err = staticTokenValidation(removeTypeInToken(token))
		} else {
			return "", false, false, errors.New(i18n[InvalidTokenValidationStrategy])
		}

		if err != nil {
			return "", false, false, err
		}

		if len(expectedRoles) == 0 {
			return userId, true, true, nil
		} else {
			isAuthorized := false
			for _, expectedRole := range expectedRoles {
				if exist(userRoles, expectedRole) {
					isAuthorized = true
					break
				}
			}

			if !isAuthorized {
				return userId, true, false, nil
			} else {
				return userId, true, true, nil
			}
		}
	}
}

func staticTokenValidation(token string) (string, []string, error) {
	parsedJWT, err := validateToken(token)

	if err != nil && parsedJWT == nil && !parsedJWT.Valid {
		return "", nil, err
	}

	claims, err := verifyJwtToken(token)

	if err != nil {
		return "", nil, err
	}

	log.Info(claims)
	// TODO: send service in header
	return "", nil, nil
}

func verifyJwtToken(tokenString string) (*jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	_, _ = jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(appCfg.TokenValidationSecretKey), nil
	})

	return &claims, nil
}

func validateToken(encodedToken string) (*jwt.Token, error) {
	decodeString, _ := base64.URLEncoding.DecodeString(appCfg.TokenValidationSecretKey)
	return jwt.Parse(encodedToken, func(token *jwt.Token) (interface{}, error) {
		if _, isValid := token.Method.(*jwt.SigningMethodHMAC); !isValid {
			return nil, errors.New(i18n[InvalidToken])

		}
		return decodeString, nil
	})
}

//callRestTokenValidationService userId userRoles error
func callRestTokenValidationService(token string) (string, []string, error) {
	request := client.R()

	request.SetHeader("Content-Type", "application/json")
	request.SetHeader("Accept", "application/json")
	request.SetResult(&TokenValidationResp{})

	u := appCfg.TokenValidationUrl + "?token=" + token
	resp, err := request.Get(u)

	if err != nil {
		log.WithFields(log.Fields{"type": Security}).Error(err)
		return "", nil, errors.New(i18n[TokenValidationConnErr])
	}

	if resp.IsError() {
		log.WithFields(log.Fields{"type": Security}).Error("Token validation response status: " + resp.Status())
		return "", nil, errors.New(i18n[TokenValidationServiceErr])
	}

	result := resp.Result().(*TokenValidationResp)

	return result.Id, result.Authorities, nil
}

//callGrpcTokenValidationService userId userRoles error
func callGrpcTokenValidationService(token string) (string, []string, error) {
	var conn *grpc.ClientConn
	conn, err := grpc.Dial(appCfg.TokenValidationUrl, grpc.WithInsecure())

	if err != nil {
		log.WithFields(log.Fields{"type": Security}).Error(err)
		return "", nil, errors.New(i18n[TokenValidationConnErr])
	}

	defer conn.Close()
	client := token_validation.NewTokenValidationServiceClient(conn)

	request := &token_validation.GetUserDetailsByTokenRequest{
		Token: token,
	}
	response, err := client.GetUserDetailsByToken(context.Background(), request)

	if err != nil {
		log.WithFields(log.Fields{"type": Security}).Error(err)
		return "", nil, errors.New(i18n[TokenValidationServiceErr])
	}
	log.WithFields(log.Fields{"type": Security}).Debugf("Validated user: %v", response.User)
	strUserID := strconv.FormatUint(response.User.GetId(), 10)
	return strUserID, response.User.GetAuthorities(), nil
}

func removeTypeInToken(token string) string {
	return strings.Replace(token, SupportedTokenType+" ", "", -1)
}

func findSuitableSecurityRule(r http.Request) *SecurityRule {
	for _, rule := range securityRules {
		if rule.Methods == nil || len(rule.Methods) == 0 || exist(rule.Methods, r.Method) {
			if comparePath(rule.Path, r.RequestURI) {
				return &rule
			}
		}
	}
	return nil
}

func comparePath(rulePath string, requestPath string) bool {
	ruleDividedPath := strings.Split(rulePath, "/")
	requestDividedPath := strings.Split(requestPath, "/")

	for i, ruleVal := range ruleDividedPath {
		if ruleVal == "**" {
			return true
		} else {
			requestVal := requestDividedPath[i]

			if ruleVal != requestVal {
				return false
			}
		}
	}

	return true
}

func genericHandler() func(http.ResponseWriter, *http.Request, martini.Params) {
	return func(w http.ResponseWriter, r *http.Request, params martini.Params) {
		path := params["_1"]
		dividedPath := strings.Split(path, "/")
		if len(dividedPath) > 0 {
			reqPrefix := dividedPath[0]

			suitableUrl := getSuitableServiceUrl(reqPrefix)

			if suitableUrl != "" {
				remote, err := url.Parse(suitableUrl)
				if err != nil {
					log.WithFields(log.Fields{"type": ReqDetail}).Error(err)
				}

				proxy := prepareProxy(remote)

				redirectPath := getRedirectPath(dividedPath)

				r.URL.Path = redirectPath

				log.WithFields(log.Fields{"type": ReqDetail}).Info(r)
				proxy.ServeHTTP(w, r)
			} else {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write(generateGenericErrorJsonStr(i18n[ServiceNotFound]))
			}
		}
	}
}

func getSuitableServiceUrl(reqPrefix string) string {
	var equivalentLocator Locator
	for _, locator := range locators {
		if locator.Prefix == reqPrefix {
			equivalentLocator = locator
			break
		}
	}

	return applyLoadBalance(equivalentLocator)
}

func applyLoadBalance(locator Locator) string {
	if len(locator.Urls) == 0 {
		return ""
	} else if len(locator.Urls) == 1 {
		return locator.Urls[0]
	} else {
		i := rand.Intn(len(locator.Urls))
		return locator.Urls[i]
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

	timeOutInt, _ := strconv.ParseInt(appCfg.TimeOut, 10, 64)
	duration := time.Duration(timeOutInt * 1000 * 1000 * 1000)
	proxy.Transport = &http.Transport{
		ResponseHeaderTimeout: duration,
	}

	proxy.ErrorHandler = func(writer http.ResponseWriter, request *http.Request, err error) {
		log.Error(err)
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusBadGateway)
		errStr := err.Error() + " Timeout: " + appCfg.TimeOut + " second."
		_, _ = writer.Write(generateGenericErrorJsonStr(errStr))
	}

	return proxy
}

func fillLocators() {
	var receiveLocatorStrategy func()
	if appCfg.LocatorSource == StaticFile {
		receiveLocatorStrategy = func() { receiveLocatorsOnFile() }
	} else if appCfg.LocatorSource == Eureka {
		receiveLocatorStrategy = func() { receiveLocatorsOnEureka() }
	} else if appCfg.LocatorSource == Consul {
		receiveLocatorStrategy = func() { receiveLocatorsOnConsul() }
	}

	_, _ = scheduler.Every(appCfg.FetchLocatorsSecond).Seconds().Run(receiveLocatorStrategy)
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

			log.WithFields(log.Fields{"type": Scheduler}).Debugf(i18n[SuccessfullyFetchOnConsul])
		}
	}
}

func getConsulServiceDetail(serviceID string) *ConsulServiceInfo {
	request := client.R()

	request.SetHeader("Content-Type", "application/json")
	request.SetHeader("Accept", "application/json")
	request.SetResult(&ConsulServiceInfo{})

	if appCfg.ConsulUsername != "" && appCfg.ConsulPassword != "" {
		request.SetBasicAuth(appCfg.ConsulPassword, appCfg.ConsulPassword)
	}

	serviceInfoUrl := appCfg.ConsulUrl + "/agent/service/" + serviceID
	infoResp, err := request.Get(serviceInfoUrl)

	if err != nil {
		log.WithFields(log.Fields{"type": Scheduler}).Error(err)
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

	if appCfg.ConsulUsername != "" && appCfg.ConsulPassword != "" {
		request.SetBasicAuth(appCfg.ConsulPassword, appCfg.ConsulPassword)
	}

	checkUrl := appCfg.ConsulUrl + "/agent/checks"
	checkResponse, err := request.Get(checkUrl)

	if err != nil {
		log.WithFields(log.Fields{"type": Scheduler}).Error(err)
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
		log.WithFields(log.Fields{"type": Scheduler}).Debugf(i18n[SuccessfullyFetchOnEureka])
	}
}

func getEurekaServices() *EurekaRegisteredServiceInfos {
	request := client.R()
	request.SetHeader("Content-Type", "application/json")
	request.SetHeader("Accept", "application/json")
	request.SetResult(&EurekaRegisteredServiceInfos{})

	if appCfg.EurekaUsername != "" && appCfg.EurekaPassword != "" {
		request.SetBasicAuth(appCfg.EurekaUsername, appCfg.EurekaPassword)
	}
	eurekaUrl := appCfg.EurekaUrl + "/eureka/apps"
	response, err := request.Get(eurekaUrl)

	if err != nil {
		log.WithFields(log.Fields{"type": Scheduler}).Error(err)
		return nil
	}

	return response.Result().(*EurekaRegisteredServiceInfos)
}

func receiveLocatorsOnFile() {
	jsonFile, err := os.Open(appCfg.LocatorFilePath)

	if err != nil {
		log.WithFields(log.Fields{"type": Scheduler}).Error(err)
	}

	defer jsonFile.Close()
	byteValue, _ := ioutil.ReadAll(jsonFile)

	var fileObj LocatorFile
	err = json.Unmarshal(byteValue, &fileObj)

	if err != nil {
		log.WithFields(log.Fields{"type": Scheduler}).Error(err)
		panic(err)
	}

	locators = fileObj.Locators
	log.WithFields(log.Fields{"type": Scheduler}).Debugf(i18n[SuccessfullyFetchOnFile])
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

func exist(source []string, search string) bool {
	for _, s := range source {
		if s == search {
			return true
		}
	}
	return false
}
