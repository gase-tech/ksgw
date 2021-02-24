package main

type ApplicationConfig struct {
	// EN, TR
	Language string `envconfig:"LANGUAGE" default:"EN"`
	// StaticFile, Eureka, Consul
	LocatorSource       string `envconfig:"LOCATOR_SOURCE" default:"STATIC_FILE"`
	LocatorFilePath     string `envconfig:"LOCATOR_FILE_PATH" default:"locators.json"`
	FetchLocatorsSecond int    `envconfig:"FETCH_LOCATORS_SECOND" default:"30"`

	EurekaUrl      string `envconfig:"EUREKA_URL" default:"http://localhost:8090"`
	EurekaUsername string `envconfig:"EUREKA_USERNAME"`
	EurekaPassword string `envconfig:"EUREKA_PASSWORD"`

	ConsulUrl      string `envconfig:"CONSUL_URL" default:"http://localhost:8500/v1"`
	ConsulUsername string `envconfig:"CONSUL_USERNAME"`
	ConsulPassword string `envconfig:"CONSUL_PASSWORD"`

	SecurityEnabled     bool   `envconfig:"SECURITY_ENABLED" default:"true"`
	SecurityYamlPath    string `envconfig:"SECURITY_YAML_PATH" default:"security.yml"`
	FetchSecuritySecond int    `envconfig:"FETCH_SECURITY_SECOND" default:"30"`

	// Grpc, Rest
	TokenValidationStrategy string `envconfig:"TOKEN_VALIDATION_STRATEGY" default:"grpc"`
	TokenValidationUrl      string `envconfig:"TOKEN_VALIDATION_URL" default:"localhost:7002"`
	CurrentUserIdHeaderKey  string `envconfig:"CURRENT_USER_ID_HEADER_KEY" default:"currentUserId"`

	TimeOut string `envconfig:"TIME_OUT" default:"60"`
	// Dev, Test, Prod -> default => Dev
	Profile string `envconfig:"PROFILE" default:"DEV"`
	Port    string `envconfig:"PORT" default:"4000"`

	CorsAllowedMethods   string `envconfig:"CORS_ALLOWED_METHODS" default:"POST, OPTIONS, GET, PUT, DELETE"`
	CorsAllowedHeaders   string `envconfig:"CORS_ALLOWED_HEADERS" default:"Content-Type, Accept-Language, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With, Origin"`
	CorsAllowCredentials bool   `envconfig:"CORS_ALLOW_CREDENTIALS" default:"true"`
	CorsAllowOrigins     string `envconfig:"CORS_ALLOW_ORIGINS" default:"*"`
}

type Locator struct {
	Prefix string   `json:"prefix"`
	Urls   []string `json:"urls"`
}

type LocatorFile struct {
	Locators []Locator `json:"locators"`
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

type GenericErrorModel struct {
	Msg string `json:"msg"`
}

type ConsulChecksResponse struct {
	Node        string   `json:"Node"`
	CheckID     string   `json:"CheckID"`
	Name        string   `json:"Name"`
	Status      string   `json:"Status"`
	Notes       string   `json:"Notes"`
	Output      string   `json:"Output"`
	ServiceID   string   `json:"ServiceID"`
	ServiceName string   `json:"ServiceName"`
	ServiceTags []string `json:"ServiceTags"`
	Type        string   `json:"Type"`
	CreateIndex int      `json:"CreateIndex"`
	ModifyIndex int      `json:"ModifyIndex"`
}

type ConsulServiceInfo struct {
	ID                string      `json:"ID"`
	Service           string      `json:"Service"`
	Tags              []string    `json:"Tags"`
	Port              int         `json:"Port"`
	Address           string      `json:"Address"`
	TaggedAddresses   interface{} `json:"TaggedAddresses"`
	EnableTagOverride bool        `json:"EnableTagOverride"`
	ContentHash       string      `json:"ContentHash"`
	Datacenter        string      `json:"Datacenter"`
}

type SecurityYaml struct {
	Rules []SecurityRule `yaml:"rules"`
}

type SecurityRule struct {
	Path    string   `yaml:"path"`
	Methods []string `yaml:"methods"`
	Roles   []string `yaml:"roles"`
}

type TokenValidationResp struct {
	Id          string   `json:"id"`
	Authorities []string `json:"authorities"`
}
