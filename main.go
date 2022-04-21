//LEAPI Voice Control API - Copyright 2022 Ruel Tmeizeh All Rights Reserved

package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

const version string = "1.0"
const serverVersion string = "RuhNet LE API v" + version
const apiVersion int = 1
const website string = "https://ruhnet.co"
const myUserAgent string = "RuhNet LE Cluster API Controller"

const timeout time.Duration = time.Duration(30 * time.Second) //Timeout for outbound requests. Adjust as needed.

var leapiconf LEAPIConfig

var startupTime time.Time
var configDir string
var domains []string
var servers []string
var syncScheme string = "http://"
var syncPort string

const banner = `
   ____         __    _    _       __
  / ___\ __  __/ /_  / \  / /__ __/ /_
 / /_/ // /_/ / _  \/ / \/ //__\_  __/
/_/  \_\\ ___/_/ /_/_/ \__/ \__,/_/   %s
_____________________________________________________
`

//////////////////////////
//Data Structs:

type LEAPIConfig struct {
	Hostname                  string `json:"hostname"`
	Username                  string `json:"user"`
	SrvDir                    string `json:"srv_dir"`
	LogFile                   string `json:"log_file"`
	HTTP_ServerPort           string `json:"http_server_port"`
	HTTPS_ServerPort          string `json:"https_server_port"`
	TLSCertFile               string `json:"tls_cert_path"`
	TLSKeyFile                string `json:"tls_key_path"`
	TLSChainFile              string `json:"tls_chain_path"`
	TLSPEMFile                string `json:"tls_pem_path"`
	TLSCAFile                 string `json:"tls_ca_path"`
	FrontEndURL               string `json:"frontend_url"`
	PrimaryDomain             string `json:"primary_domain"`
	LetsEncryptValidationPath string `json:"letsencrypt_validation_path"`
	ReloadCommand             string `json:"reload_command"`
	RenewAllow                string `json:"renew_allow_days"`
	SecretKey                 string `json:"secret_key"`
	Production                bool   `json:"production"`
	CheckPort                 string `json:"check_port"`
}

type UpOut struct {
	Up        bool      `json:"up,omitempty"`
	StartTime time.Time `json:"start_time,omitempty"`
	Uptime    string    `json:"uptime,omitempty"`
}

type APIOutput struct {
	Status  int      `json:"status,omitempty"`
	Message string   `json:"message,omitempty"`
	Data    []string `json:"data,omitempty"`
}

type keypairReloader struct {
	certMu   sync.RWMutex
	cert     *tls.Certificate
	certPath string
	keyPath  string
}

func main() {
	/////////////////////////////////////////////
	startupTime = time.Now()

	//Read config:
	configFilename := "leapi_config.json"
	configDir = os.Getenv("LEAPI_CONFDIR")
	if configDir == "" {
		confDirs := []string{
			"/usr/local/etc",
			"/opt/leapi",
			"/opt/leapi/etc",
			"/var/lib/leapi",
			"/etc",
		}
		configDir = "." //the fallback
		for _, cd := range confDirs {
			if _, err := os.Stat(cd + "/" + configFilename); os.IsNotExist(err) { //doesn't exist...
				continue //..so check next one
			}
			configDir = cd
		}
	}
	configFile := configDir + "/" + configFilename
	jsonFile, err := os.Open(configFile)
	if err != nil {
		log.Fatal("Could not open config file: " + configFile + "\n" + err.Error())
	}
	defer jsonFile.Close()
	fileBytes, _ := ioutil.ReadAll(jsonFile)

	//strip out // comments from config file:
	re := regexp.MustCompile(`([\s]//.*)|(^//.*)`)
	fileCleanedBytes := re.ReplaceAll(fileBytes, nil)
	//fmt.Println(string(fileCleanedBytes))

	err = json.Unmarshal(fileCleanedBytes, &leapiconf) //populate the config struct with JSON data from the config file
	if err != nil {
		log.Fatal("Could not parse config file: " + configFile + "\n" + err.Error())
	}

	leapiconf.checkConfig()

	log.Println("Configuration OK, starting LEAPI...")
	fmt.Println()

	leapiLogFile, err := os.OpenFile(leapiconf.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0664)
	if err != nil {
		log.Println("Could not open log file: " + leapiconf.LogFile + "\n" + err.Error())
		leapiLogFile, err = os.OpenFile("/tmp/leapi.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0664)
		if err != nil {
			log.Fatal("Can't open even /tmp log file!\n" + err.Error())
		}
	}
	defer leapiLogFile.Close()
	//set other logging to same file
	log.SetOutput(leapiLogFile)

	//Startup Banner
	fmt.Printf(banner, website)
	fmt.Println(serverVersion + "\n")

	//read domains file
	domainsFile := configDir + "/domains.json"
	if fileExists(domainsFile) {
		jsonFile, err = os.Open(domainsFile)
		if err != nil {
			log.Fatal("Could not open domains.json file: " + err.Error())
		}
		defer jsonFile.Close()
		fileBytes, err := ioutil.ReadAll(jsonFile)
		err = json.Unmarshal(fileBytes, &domains)
		if err != nil {
			log.Fatal("Could not parse domains.json file: " + err.Error())
		}
	}

	//read servers file
	serversFile := configDir + "/servers.json"
	if fileExists(serversFile) {
		jsonFile, err = os.Open(serversFile)
		if err != nil {
			log.Fatal("Could not open servers.json file: " + err.Error())
		}
		defer jsonFile.Close()
		fileBytes, err := ioutil.ReadAll(jsonFile)
		err = json.Unmarshal(fileBytes, &servers)
		if err != nil {
			log.Fatal("Could not parse servers.json file: " + err.Error())
		}
	}

	syncPort = leapiconf.HTTP_ServerPort
	if leapiconf.LetsEncryptValidationPath == "-" {
		leapiconf.LetsEncryptValidationPath = leapiconf.SrvDir + "/acme-challenge"
	}

	/////////////////////////////////////////////
	//Echo config:
	e := echo.New() // Echo instance

	e.HideBanner = true
	e.Use(middleware.Recover())
	//e.Logger.SetLevel(stdLog.DEBUG)
	//e.Debug = true
	//e.Use(middleware.Logger())
	/*
		e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{
			Output: leapiLogFile,
		}))
	*/

	/////////////////////////////////////////////
	// ROUTE GROUPS
	api := e.Group("/api") //API routes
	/////////////////////////////////////////////

	/////////////////////////////////////////////
	// MIDDLEWARE
	//Add server header and CORS
	e.Use(serverHeaders)
	//Auth API routes
	api.Use(middleware.KeyAuth(apiKeyAuth))
	/////////////////////////////////////////////

	/////////////////////////////////////////////
	// ROUTES:

	e.HEAD("/", uptimeCheck)
	e.HEAD("/up", uptimeCheck)
	e.GET("/up", uptimeCheck)
	e.HEAD("/_up", uptimeCheck)
	e.GET("/_up", uptimeCheck)

	e.Static("/.well-known/acme-challenge", leapiconf.LetsEncryptValidationPath) //Lets Encrypt validation path

	/////////////////////////////////
	//        API Routes           //
	/////////////////////////////////

	api.OPTIONS("/domains", apiListDomains)
	api.GET("/domains", apiListDomains)
	api.OPTIONS("/domains/:domain", apiPutDomain)
	api.PUT("/domains/:domain", apiPutDomain)
	api.DELETE("/domains/:domain", apiDeleteDomain)

	api.OPTIONS("/servers", apiListServers)
	api.GET("/servers", apiListServers)
	api.OPTIONS("/servers/:server", apiPutServer)
	api.PUT("/servers/:server", apiPutServer)
	api.DELETE("/servers/:server", apiDeleteServer)

	api.OPTIONS("/sync/:host", apiSync)
	api.POST("/sync/:host", apiSync)

	api.OPTIONS("/renew", apiRenew)
	api.POST("/renew", apiRenew)

	/////////////////////////////////////////////
	// HTTP SERVERS CONFIG:

	//TLS Server
	if leapiconf.HTTPS_ServerPort != "-" { //disable HTTPS if port is zero

		syncScheme = "https://"
		syncPort = leapiconf.HTTPS_ServerPort

		//certPair, err := tls.LoadX509KeyPair(leapiconf.TLSCertificateFile, leapiconf.TLSKeyFile)
		if !fileExists(leapiconf.TLSCertFile) || !fileExists(leapiconf.TLSKeyFile) {
			fmt.Println("Provided certificate and/or key file does not exist! Terminating.")
			log.Fatal("Provided certificate and/or key file does not exist! Terminating.")
		}

		//Create loader for cert files
		kpr, err := NewKeypairReloader(leapiconf.TLSCertFile, leapiconf.TLSKeyFile)
		if err != nil {
			log.Fatal(err)
		}

		tlsConfig := &tls.Config{
			//MinVersion: tls.VersionTLS10,
			MinVersion: tls.VersionTLS12,
			//CurvePreferences:         []tls.CurveID{tls.X25519, tls.CurveP521, tls.CurveP384, tls.CurveP256},
			CurvePreferences:         []tls.CurveID{tls.X25519, tls.CurveP256}, //these two have fast assembly implementations
			PreferServerCipherSuites: true,
			//Certificates:             []tls.Certificate{certPair},
			//Use loader instead of certPair
			GetCertificate: kpr.GetCertificateFunc(),
		}

		srvTLS := &http.Server{
			Addr:         ":" + leapiconf.HTTPS_ServerPort,
			ReadTimeout:  120 * time.Second,
			WriteTimeout: 120 * time.Second,
			IdleTimeout:  120 * time.Second,
			TLSConfig:    tlsConfig,
		}

		//Start TLS Server
		go func(c *echo.Echo) {
			e.Logger.Fatal(e.StartServer(srvTLS))
		}(e)
	}

	//HTTP Server
	srvHTTP := &http.Server{
		Addr:         ":" + leapiconf.HTTP_ServerPort,
		ReadTimeout:  120 * time.Second,
		WriteTimeout: 120 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	//Start HTTP Server
	e.Logger.Fatal(e.StartServer(srvHTTP))

} //func main()

func (f *LEAPIConfig) checkConfig() {
	var invalid bool
	val := reflect.ValueOf(f).Elem()
	fmt.Println()
	for i := 0; i < val.NumField(); i++ {
		valueField := val.Field(i)
		if valueField.Interface() == "" || valueField.Interface() == nil || valueField.Interface() == 0 {
			if !invalid {
				log.Println("===========| ERRORS IN 'leapi_config.json' CONFIG FILE: |================")
				color.Red("--------------------------------------------------------------------------------")
				color.Red(" ===========| ERRORS IN 'leapi_config.json' CONFIG FILE: |================")
				color.Red("--------------------------------------------------------------------------------")
			}
			invalid = true
			log.Printf("      - Required config item '%s' missing or invalid.\n", val.Type().Field(i).Tag.Get("json"))
			fmt.Printf("      - Required config item '%s' missing or invalid.\n", val.Type().Field(i).Tag.Get("json"))
		}
	}
	if invalid {
		color.Red("--------------------------------------------------------------------------------")
		log.Fatal("Exiting!")
	}
}

//This middleware adds headers to the response, for server version and CORS origin.
func serverHeaders(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		c.Response().Header().Set(echo.HeaderServer, serverVersion)
		c.Response().Header().Set("Access-Control-Allow-Origin", leapiconf.FrontEndURL)
		c.Response().Header().Set("Access-Control-Allow-Methods", "GET, PUT, POST, DELETE")
		//c.Response().Header().Set("Access-Control-Allow-Headers", leapiconf.AllowedHeaders)
		c.Response().Header().Set("Access-Control-Allow-Headers",
			strings.Join([]string{
				echo.HeaderOrigin,
				"X-Auth-Token",
				echo.HeaderContentType,
				echo.HeaderAccept,
				echo.HeaderAuthorization,
			}, ", "))

		return next(c)
	}
}

func apiKeyAuth(key string, c echo.Context) (bool, error) {
	return (key == leapiconf.SecretKey), nil
}

func NewKeypairReloader(certPath, keyPath string) (*keypairReloader, error) {
	result := &keypairReloader{
		certPath: certPath,
		keyPath:  keyPath,
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	result.cert = &cert
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGHUP)
		for range c {
			log.Printf("Received SIGHUP, reloading TLS certificate and key from %q and %q", leapiconf.TLSCertFile, leapiconf.TLSKeyFile)
			fmt.Printf("Received SIGHUP, reloading TLS certificate and key from %q and %q\n", leapiconf.TLSCertFile, leapiconf.TLSKeyFile)
			if err := result.maybeReload(); err != nil {
				log.Printf("Keeping old TLS certificate because the new one could not be loaded: %v", err)
				fmt.Printf("Keeping old TLS certificate because the new one could not be loaded: %v", err)
			}
		}
	}()
	return result, nil
}

func (kpr *keypairReloader) maybeReload() error {
	newCert, err := tls.LoadX509KeyPair(kpr.certPath, kpr.keyPath)
	if err != nil {
		return err
	}
	kpr.certMu.Lock()
	defer kpr.certMu.Unlock()
	kpr.cert = &newCert
	return nil
}

func (kpr *keypairReloader) GetCertificateFunc() func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		kpr.certMu.RLock()
		defer kpr.certMu.RUnlock()
		return kpr.cert, nil
	}
}

func okOut() (int, APIOutput) {
	var out APIOutput
	out.Message = "success"
	out.Status = http.StatusOK
	return out.Status, out
}

func errorOut(status int, msg string) (int, APIOutput) {
	var out APIOutput
	out.Message = msg
	out.Status = status
	return out.Status, out
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func writeDomains() error {
	b := new(bytes.Buffer)
	err := json.NewEncoder(b).Encode(domains)
	if err != nil {
		return errors.New("Couldn't encode domains list into JSON: " + err.Error())
	}

	err = ioutil.WriteFile(configDir+"/domains.json", b.Bytes(), 0644)
	if err != nil {
		return errors.New("Couldn't write domains file: " + configDir + "/domains.json")
	}

	return nil
}

func writeServers() error {
	b := new(bytes.Buffer)
	err := json.NewEncoder(b).Encode(servers)
	if err != nil {
		return errors.New("Couldn't encode servers list into JSON: " + err.Error())
	}

	err = ioutil.WriteFile(configDir+"/servers.json", b.Bytes(), 0644)
	if err != nil {
		return errors.New("Couldn't write servers file: " + configDir + "/servers.json")
	}

	return nil
}

func syncAllServers() error {
	var theError error
	numservers := len(servers)
	c := make(chan string)

	var wg sync.WaitGroup
	wg.Add(numservers)
	for n := 0; n < numservers; n++ {
		go func(c chan string) {
			for {
				srv, more := <-c
				if more == false {
					wg.Done()
					return
				}

				log.Println("Parallel execution sync of server: " + srv + "...")
				err := syncOneServer(srv)
				if err != nil {
					log.Println(err.Error)
					theError = err
				}
			}
		}(c)
	}
	for _, server := range servers { //send each server to the channel
		if server == leapiconf.Hostname { //don't send myself
			continue
		}
		c <- server
	}
	close(c)
	wg.Wait()
	log.Println("Finished sending sync requests.")

	return theError //if any one or more fail, return an error for it (the last one that fails)
}

func syncOneServer(server string) error {
	//Make http requests to each other servers' /sync endpoints
	// https://server.tld:port/sync
	log.Println("SYNC " + server + " starting...")
	req, err := http.NewRequest("POST", syncScheme+server+":"+syncPort+"/api/sync/"+leapiconf.Hostname, nil)
	if err != nil {
		log.Println(err.Error())
		return errors.New("Couldn't create new HTTP sync request for server: " + server)
	}
	req.Close = true
	req.Header.Set("User-Agent", myUserAgent)
	req.Header.Set("Authorization", "Bearer "+leapiconf.SecretKey)
	//skip verification of cert for https syncing, since the cert may not be setup properly at first
	customTransport := http.DefaultTransport.(*http.Transport).Clone()
	customTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := &http.Client{Transport: customTransport, Timeout: timeout}
	//client := &http.Client{Timeout: timeout}
	response, err := client.Do(req)
	if err != nil {
		log.Println(err.Error())
		return errors.New("Couldn't perform HTTP sync request to server: " + server)
	}
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Println(err.Error())
		return errors.New("Couldn't parse response body on request to server: " + server)
	}
	if response.StatusCode != 200 {
		errorString := "Problem syncing to server " + server + ". Status code: " + strconv.Itoa(response.StatusCode) + " Body: " + string(body)
		log.Println(errorString)
		return errors.New(errorString)
	}
	log.Println("SYNC " + server + " success!")
	return nil
}

func syncServersFromHost(host string) error {
	var theError error
	req, err := http.NewRequest("GET", syncScheme+host+":"+syncPort+"/api/servers", nil)
	if err != nil {
		log.Println(err.Error())
		return errors.New("Couldn't create new HTTP request for syncing servers from host: " + host)
	}
	req.Close = true
	req.Header.Set("User-Agent", myUserAgent)
	req.Header.Set("Authorization", "Bearer "+leapiconf.SecretKey)
	//skip verification of cert for https syncing, since the cert may not be setup properly at first
	customTransport := http.DefaultTransport.(*http.Transport).Clone()
	customTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := &http.Client{Transport: customTransport, Timeout: timeout}
	//client := &http.Client{Timeout: timeout}
	response, err := client.Do(req)
	if err != nil {
		log.Println(err.Error())
		return errors.New("Couldn't perform HTTP server sync request to host: " + host)
	}
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Println(err.Error())
		return errors.New("Couldn't parse response body from server sync request to server: " + host)
	}
	if response.StatusCode != 200 {
		theError = errors.New("Problem syncing servers from host " + host + ". Status code: " + strconv.Itoa(response.StatusCode) + " Body: " + string(body))
		log.Println(theError.Error())
		return theError
	}

	var result APIOutput
	err = json.Unmarshal(body, &result)
	if err != nil {
		log.Println(err.Error())
		return errors.New("Couldn't parse response body from host " + host + ": " + err.Error())
	}
	servers = result.Data

	err = writeServers()
	if err != nil {
		log.Println(err.Error())
		return err
	}

	return nil
}

func syncDomainsFromHost(host string) error {
	var theError error
	req, err := http.NewRequest("GET", syncScheme+host+":"+syncPort+"/api/domains", nil)
	if err != nil {
		log.Println(err.Error())
		return errors.New("Couldn't create new HTTP request for syncing domains from host: " + host)
	}
	req.Close = true
	req.Header.Set("User-Agent", myUserAgent)
	req.Header.Set("Authorization", "Bearer "+leapiconf.SecretKey)
	//skip verification of cert for https syncing, since the cert may not be setup properly at first
	customTransport := http.DefaultTransport.(*http.Transport).Clone()
	customTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := &http.Client{Transport: customTransport, Timeout: timeout}
	//client := &http.Client{Timeout: timeout}
	response, err := client.Do(req)
	if err != nil {
		log.Println(err.Error())
		return errors.New("Couldn't perform HTTP domain sync request to host: " + host)
	}
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Println(err.Error())
		return errors.New("Couldn't parse response body from domain sync request to server: " + host)
	}
	if response.StatusCode != 200 {
		theError = errors.New("Problem syncing domains from host " + host + ". Status code: " + strconv.Itoa(response.StatusCode) + " Body: " + string(body))
		log.Println(theError.Error())
		return theError
	}

	var result APIOutput
	err = json.Unmarshal(body, &result)
	if err != nil {
		log.Println(err.Error())
		return errors.New("Couldn't parse response body from host " + host + ": " + err.Error())
	}
	domains = result.Data

	err = writeDomains()
	if err != nil {
		log.Println(err.Error())
		return err
	}

	return nil
}

func renew() error {
	log.Println("Renew operation initiated...")
	//BUILD/SET GETSSL ENVIRONMENT VARIABLES THEN EXECUTE GETSSL

	//domain list
	var domainlist string
	for _, d := range domains {
		if d == leapiconf.PrimaryDomain { //ignore primary domain
			continue
		}
		domainlist = domainlist + "," + d
	}
	domainlist = strings.TrimLeft(domainlist, ",") //Take off leading comma
	err := os.Setenv("SANS", domainlist)
	if err != nil {
		return errors.New("RENEW: error setting SANS domains list environment variable: " + err.Error())
	}
	fmt.Println(domainlist)

	//ACL string
	//aclstring := "(" + leapiconf.LetsEncryptValidationPath
	aclstring := leapiconf.LetsEncryptValidationPath
	for _, server := range servers {
		if server == leapiconf.Hostname {
			continue
		}
		aclstring += ";ssh:" + leapiconf.Username + "@" + server + ":" + leapiconf.LetsEncryptValidationPath
	}
	//aclstring = aclstring + ")"
	err = os.Setenv("ACL", aclstring)
	if err != nil {
		return errors.New("RENEW: error setting ACL environment variable: " + err.Error())
	}
	fmt.Println(aclstring)

	//Cert and key locations
	domain_cert_location := leapiconf.TLSCertFile
	for _, server := range servers {
		if server == leapiconf.Hostname {
			continue
		}
		domain_cert_location += ";ssh:" + leapiconf.Username + "@" + server + ":" + leapiconf.TLSCertFile
	}
	err = os.Setenv("DOMAIN_CERT_LOCATION", domain_cert_location)
	if err != nil {
		return errors.New("RENEW: error setting DOMAIN_CERT_LOCATION environment variable: " + err.Error())
	}
	fmt.Println(domain_cert_location)

	domain_key_location := leapiconf.TLSKeyFile
	for _, server := range servers {
		if server == leapiconf.Hostname {
			continue
		}
		domain_key_location += ";ssh:" + leapiconf.Username + "@" + server + ":" + leapiconf.TLSKeyFile
	}
	err = os.Setenv("DOMAIN_KEY_LOCATION", domain_key_location)
	if err != nil {
		return errors.New("RENEW: error setting DOMAIN_KEY_LOCATION environment variable: " + err.Error())
	}

	domain_chain_location := leapiconf.TLSChainFile
	for _, server := range servers {
		if server == leapiconf.Hostname {
			continue
		}
		domain_chain_location += ";ssh:" + leapiconf.Username + "@" + server + ":" + leapiconf.TLSChainFile
	}
	err = os.Setenv("DOMAIN_CHAIN_LOCATION", domain_chain_location)
	if err != nil {
		return errors.New("RENEW: error setting DOMAIN_CHAIN_LOCATION environment variable: " + err.Error())
	}

	domain_pem_location := leapiconf.TLSPEMFile
	for _, server := range servers {
		if server == leapiconf.Hostname {
			continue
		}
		domain_pem_location += ";ssh:" + leapiconf.Username + "@" + server + ":" + leapiconf.TLSPEMFile
	}
	err = os.Setenv("DOMAIN_PEM_LOCATION", domain_pem_location)
	if err != nil {
		return errors.New("RENEW: error setting DOMAIN_PEM_LOCATION environment variable: " + err.Error())
	}

	//these parameters don't seem to be respected by gettssl from environment variables, so write them to config file:
	ca_cert_location := leapiconf.TLSCAFile
	for _, server := range servers {
		if server == leapiconf.Hostname {
			continue
		}
		ca_cert_location += ";ssh:" + leapiconf.Username + "@" + server + ":" + leapiconf.TLSCAFile
	}

	reload_command := leapiconf.ReloadCommand
	for _, server := range servers {
		if server == leapiconf.Hostname {
			continue
		}
		reload_command += "; ssh " + leapiconf.Username + "@" + server + " '" + leapiconf.ReloadCommand + "'"
	}

	ca_server := "https://acme-staging-v02.api.letsencrypt.org"
	if leapiconf.Production {
		ca_server = "https://acme-v02.api.letsencrypt.org"
	}

	var configFile string

	configFile = "CA=\"" + ca_server + "\"\n"
	configFile += "USE_SINGLE_ACL=\"true\"\n"
	configFile += "CA_CERT_LOCATION=\"" + leapiconf.TLSCAFile + "\"\n"
	configFile += "RELOAD_CMD=\"" + reload_command + "\"\n"
	configFile += "RENEW_ALLOW=\"" + leapiconf.RenewAllow + "\"\n"
	configFile += "CHECK_REMOTE=\"true\"\n"
	configFile += "SERVER_TYPE=\"" + leapiconf.CheckPort + "\"\n"
	configFile += "CHECK_REMOTE_WAIT=\"5\"\n"

	//write config file
	err = ioutil.WriteFile(configDir+"/"+leapiconf.PrimaryDomain+"/getssl.cfg", []byte(configFile), 0644)
	if err != nil {
		return errors.New("Couldn't write getssl config file: " + configDir + "/" + leapiconf.PrimaryDomain + "/getssl.cfg")
	}

	/*
		//////PRINT VARS
		fmt.Println()
		for _, e := range os.Environ() {
			fmt.Println(e)
		}
	*/

	//RUN GETSSL
	//run getssl on primary domain to renew
	//cmd := exec.Command(leapiconf.SrvDir+"/getssl", "-u", "-w", leapiconf.SrvDir, leapiconf.PrimaryDomain)
	cmd := exec.Command(leapiconf.SrvDir+"/getssl", "-w", leapiconf.SrvDir, leapiconf.PrimaryDomain)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Println("BEGIN GETSSL OUTPUT:")
		log.Println(string(output))
		log.Println("END GETSSL OUTPUT")
		return errors.New("RENEW: execution of getssl failed: " + err.Error())
	}

	log.Println("BEGIN GETSSL OUTPUT:")
	log.Println(string(output))
	log.Println("END GETSSL OUTPUT")

	return nil
}

func uptime() UpOut {
	uptime := fmt.Sprintf("%s", time.Since(startupTime))

	out := UpOut{
		Up:        true,
		StartTime: startupTime,
		Uptime:    uptime,
	}

	return out
}

/////////////////////////////////////////////
///// API ROUTE FUNCTIONS
/////////////////////////////////////////////
func uptimeCheck(c echo.Context) error {
	if c.Request().Method == http.MethodHead {
		return c.NoContent(http.StatusOK)
	}
	//return c.String(http.StatusOK, "{\"up\":true}")
	return c.JSON(http.StatusOK, uptime())
}

func apiRenew(c echo.Context) error {
	err := renew()
	if err != nil {
		return c.JSON(errorOut(http.StatusInternalServerError, "Error renewing: "+err.Error()))
	}
	return c.JSON(okOut())
}

func apiListDomains(c echo.Context) error {
	var out APIOutput
	out.Status = http.StatusOK
	out.Message = "domains list"
	out.Data = domains
	return c.JSON(out.Status, out)
}

func apiPutDomain(c echo.Context) error {
	domain := c.Param("domain")

	//check for dups
	for _, d := range domains {
		if d == domain {
			return c.JSON(errorOut(http.StatusBadRequest, "Bad request: Domain already exists."))
		}
	}

	//add domain to list
	domains = append(domains, domain)

	//write list to disk
	err := writeDomains()
	if err != nil {
		log.Println(err.Error())
		return c.JSON(errorOut(http.StatusInternalServerError, "Error writing domains list to disk: "+err.Error()))
	}

	//sync with other servers
	err = syncAllServers()
	if err != nil {
		log.Println(err.Error())
		return c.JSON(errorOut(http.StatusInternalServerError, "Error syncing to other servers: "+err.Error()))
	}

	//renew cert
	err = renew()
	if err != nil {
		log.Println(err.Error())
		return c.JSON(errorOut(http.StatusInternalServerError, "Error renewing: "+err.Error()))
	}

	return c.JSON(okOut())
}

func apiDeleteDomain(c echo.Context) error {
	deleteDomain := c.Param("domain")
	var newlist []string
	for _, d := range domains {
		if d != deleteDomain {
			newlist = append(newlist, d)
		}
	}

	domains = newlist

	//write list to disk
	err := writeDomains()
	if err != nil {
		log.Println(err.Error())
		return c.JSON(errorOut(http.StatusInternalServerError, "Error writing domains list to disk: "+err.Error()))
	}

	//sync with other servers
	err = syncAllServers()
	if err != nil {
		log.Println(err.Error())
		return c.JSON(errorOut(http.StatusInternalServerError, "Error syncing to other servers: "+err.Error()))
	}

	//renew cert
	err = renew()
	if err != nil {
		log.Println(err.Error())
		return c.JSON(errorOut(http.StatusInternalServerError, "Error renewing: "+err.Error()))
	}

	return c.JSON(okOut())
}

func apiListServers(c echo.Context) error {
	var out APIOutput
	out.Status = http.StatusOK
	out.Message = "servers list"
	out.Data = servers
	return c.JSON(out.Status, out)
}

func apiPutServer(c echo.Context) error {
	server := c.Param("server")

	//check for dups
	for _, s := range servers {
		if s == server {
			return c.JSON(errorOut(http.StatusBadRequest, "Bad request: Server already exists."))
		}
	}

	//add servers to list
	servers = append(servers, server)

	//write list to disk
	err := writeServers()
	if err != nil {
		log.Println(err.Error())
		return c.JSON(errorOut(http.StatusInternalServerError, "Error writing servers list to disk: "+err.Error()))
	}

	//sync with other servers
	err = syncAllServers()
	if err != nil {
		log.Println(err.Error())
		return c.JSON(errorOut(http.StatusInternalServerError, "Error syncing to other servers: "+err.Error()))
	}

	//renew cert
	err = renew()
	if err != nil {
		log.Println(err.Error())
		return c.JSON(errorOut(http.StatusInternalServerError, "Error renewing: "+err.Error()))
	}

	return c.JSON(okOut())
}

func apiDeleteServer(c echo.Context) error {
	deleteServer := c.Param("server")

	var newlist []string
	for _, s := range servers {
		if s != deleteServer {
			newlist = append(newlist, s)
		}
	}
	servers = newlist

	//write list to disk
	err := writeServers()
	if err != nil {
		log.Println(err.Error())
		return c.JSON(errorOut(http.StatusInternalServerError, "Error writing servers list to disk: "+err.Error()))
	}

	//sync with other servers
	err = syncAllServers()
	if err != nil {
		log.Println(err.Error())
		return c.JSON(errorOut(http.StatusInternalServerError, "Error syncing to other servers: "+err.Error()))
	}

	//renew cert
	err = renew()
	if err != nil {
		log.Println(err.Error())
		return c.JSON(errorOut(http.StatusInternalServerError, "Error renewing: "+err.Error()))
	}

	return c.JSON(okOut())
}

func apiSync(c echo.Context) error {
	host := c.Param("host")

	log.Println("Received sync request for host: " + host + ". From IP address: " + c.RealIP() + " Syncing...")

	err := syncServersFromHost(host)
	if err != nil {
		log.Println(err.Error())
		return c.JSON(errorOut(http.StatusInternalServerError, "Error syncing servers from host: "+host+". "+err.Error()))
	}

	err = syncDomainsFromHost(host)
	if err != nil {
		log.Println(err.Error())
		return c.JSON(errorOut(http.StatusInternalServerError, "Error syncing domains from host: "+host+". "+err.Error()))
	}

	return c.JSON(okOut())
}
