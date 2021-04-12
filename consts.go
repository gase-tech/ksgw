package main

const (
	// LOG TYPES
	ReqDetail = "REQUEST_DETAIL"
	Scheduler = "SCHEDULER"
	Config    = "CONFIG"
	Security  = "SECURITY"

	// HEADER
	ReqUuid            = "REQ_UUID"
	Authorization      = "Authorization"
	SupportedTokenType = "Bearer"

	// Locator Source
	StaticFile = "STATIC_FILE"
	Eureka     = "EUREKA"
	Consul     = "CONSUL"

	// Consul Check Statuses
	Passing  = "passing"
	Warning  = "warning"
	Critical = "critical"

	// Token Validation Strategy
	Grpc   = "grpc"
	Rest   = "rest"
	Static = "static"

	// Profiles
	Dev  = "DEV"
	Test = "TEST"
	Prod = "PROD"

	// Languages
	EN = "EN"
	TR = "TR"

	// Messages
	ServiceNotFound                = "ServiceNotFound"
	SuccessfullyFetchOnFile        = "SuccessfullyFetchOnFile"
	SuccessfullyFetchOnEureka      = "SuccessfullyFetchOnEureka"
	SuccessfullyFetchOnConsul      = "SuccessfullyFetchOnConsul"
	SecurityConfigUpdated          = "SecurityConfigUpdated"
	RequireAuthentication          = "RequireAuthentication"
	RequireAuthorization           = "RequireAuthorization"
	InvalidTokenSyntax             = "InvalidTokenSyntax"
	TokenValidationConnErr         = "TokenValidationConnErr"
	TokenValidationServiceErr      = "TokenValidationServiceErr"
	InvalidTokenValidationStrategy = "InvalidTokenValidationStrategy"
	GenericError                   = "GenericError"
)
