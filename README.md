# KSWG <a href="https://golang.org" target="_blank"> <img src="https://raw.githubusercontent.com/devicons/devicon/master/icons/go/go-original.svg" alt="go" width="40" height="40"/> </a>

## Environments

```bash
Name: LANGUAGE (EN/TR)
Default: EN
Desc: i18n language setting
```
```bash
Name: LOCATOR_SOURCE (STATIC_FILE/EUREKA/CONSUL)
Default: STATIC_FILE
Desc: source to receive routing rules  
```
```bash
Name: LOCATOR_FILE_PATH
Default: locators.json
Desc: routing rules json path if locator source is static file 
```
```bash
Name: FETCH_LOCATORS_SECOND
Default: 30
Desc: routing source update period as second
```
```bash
Name: EUREKA_URL
Default: http://localhost:8090
Desc: eureka server url if locator source is eureka
```
```bash
Name: EUREKA_USERNAME
Desc: eureka server username if locator source is eureka
```
```bash
Name: EUREKA_PASSWORD
Desc: eureka server password if locator source is eureka
```
```bash
Name: CONSUL_URL
Default: http://localhost:8500/v1
Desc: consul server url if locator source is consul
```
```bash
Name: CONSUL_USERNAME
Desc: consul server useranme if locator source is consul
```
```bash
Name: CONSUL_PASSWORD
Desc: consul server password if locator source is consul
```
```bash
Name: SECURITY_ENABLED
Default: true
```
```bash
Name: SECURITY_YAML_PATH
Default: security.yml
Desc: routing security rules json path if security is enable 
```
```bash
Name: FETCH_SECURITY_SECOND
Default: 30
Desc: routing security rules update period as second
```
```bash
Name: TOKEN_VALIDATION_STRATEGY (grpc/rest)
Default: grpc
Desc: token validation service call method
```
```bash
Name: TOKEN_VALIDATION_URL
Default: localhost:7002
Desc: token service url
```
```bash
Name: CURRENT_USER_ID_HEADER_KEY
Default: currentUserId
Desc: header name for will be passed user id  
```
```bash
Name: TIME_OUT
Default: 60 (second)
Desc: validity period of the forwarded request
```
```bash
Name: PROFILE (DEV/TEST/PROD)
Default: DEV
```
```bash
Name: PORT
Default: 4000
```
```bash
Name: CORS_ALLOWED_METHODS
Default: POST, OPTIONS, GET, PUT, DELETE
```
```bash
Name: CORS_ALLOWED_HEADERS
Default: Content-Type, Accept-Language, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With, Origin
```
```bash
Name: CORS_ALLOW_CREDENTIALS
Default: true
```
```bash
Name: CORS_ALLOW_ORIGINS
Default: *
```

## DOCKER

```bash
docker build -t ksgw .
```

```bash
(in project folder)
docker run -d -p 4000:4000 --name ksgw --link badger:badger --env-file env.list ksgw
```

## License
[APACHE-2.0](https://choosealicense.com/licenses/apache-2.0/)