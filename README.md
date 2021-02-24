# KSWG <a href="https://golang.org" target="_blank"> <img src="https://raw.githubusercontent.com/devicons/devicon/master/icons/go/go-original.svg" alt="go" width="40" height="40"/> </a>

## Environments

```bash
Name: Language (EN/TR)
Default: EN
Desc: i18n language setting
```
```bash
Name: LocatorSource (STATIC_FILE/EUREKA/CONSUL)
Default: STATIC_FILE
Desc: source to receive routing rules  
```
```bash
Name: LocatorFilePath
Default: locators.json
Desc: routing rules json path if locator source is static file 
```
```bash
Name: FetchLocatorsSecond
Default: 30
Desc: routing source update period as second
```
```bash
Name: EurekaUrl
Default: http://localhost:8090
Desc: eureka server url if locator source is eureka
```
```bash
Name: EurekaUsername
Desc: eureka server username if locator source is eureka
```
```bash
Name: EurekaUsername
Desc: eureka server password if locator source is eureka
```
```bash
Name: ConsulUrl
Default: http://localhost:8500/v1
Desc: consul server url if locator source is consul
```
```bash
Name: ConsulUsername
Desc: consul server useranme if locator source is consul
```
```bash
Name: ConsulPassword
Desc: consul server password if locator source is consul
```
```bash
Name: SecurityEnabled
Default: true
```
```bash
Name: SecurityYamlPath
Default: security.yml
Desc: routing security rules json path if security is enable 
```
```bash
Name: FetchSecuritySecond
Default: 30
Desc: routing security rules update period as second
```
```bash
Name: TokenValidationStrategy (grpc/rest)
Default: grpc
Desc: token validation service call method
```
```bash
Name: TokenValidationUrl
Default: localhost:7002
Desc: token service url
```
```bash
Name: CurrentUserIdHeaderKey
Default: currentUserId
Desc: header name for will be passed user id  
```
```bash
Name: TimeOut
Default: 60 (second)
Desc: validity period of the forwarded request
```
```bash
Name: Profile (DEV/TEST/PROD)
Default: DEV
```
```bash
Name: Port
Default: 4000
```
```bash
Name: CorsAllowedMethods
Default: POST, OPTIONS, GET, PUT, DELETE
```
```bash
Name: CorsAllowedHeaders
Default: Content-Type, Accept-Language, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With, Origin
```
```bash
Name: CorsAllowCredentials
Default: true
```
```bash
Name: CorsAllowOrigins
Default: *
```


## License
[APACHE-2.0](https://choosealicense.com/licenses/apache-2.0/)