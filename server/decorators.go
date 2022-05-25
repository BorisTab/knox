package server

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/gorilla/context"
	"github.com/pavelzhurov/knox"
	"github.com/pavelzhurov/knox/log"
	"github.com/pavelzhurov/knox/server/auth"
)

type contextKey int

const (
	apiErrorContext contextKey = iota
	principalContext
	paramsContext
	dbContext
	idContext
)

// GetAPIError gets the HTTP error that will be returned from the server.
func GetAPIError(r *http.Request) *HTTPError {
	if rv := context.Get(r, apiErrorContext); rv != nil {
		return rv.(*HTTPError)
	}
	return nil
}

func setAPIError(r *http.Request, val *HTTPError) {
	context.Set(r, apiErrorContext, val)
}

// GetPrincipal gets the principal authenticated through the authentication decorator
func GetPrincipal(r *http.Request) knox.Principal {
	if rv := context.Get(r, principalContext); rv != nil {
		return rv.(knox.Principal)
	}
	return nil
}

func setPrincipal(r *http.Request, val knox.Principal) {
	context.Set(r, principalContext, val)
}

// GetParams gets the parameters for the request through the parameters context.
func GetParams(r *http.Request) map[string]string {
	if rv := context.Get(r, paramsContext); rv != nil {
		return rv.(map[string]string)
	}
	return nil
}

func setParams(r *http.Request, val map[string]string) {
	context.Set(r, paramsContext, val)
}

func getDB(r *http.Request) KeyManager {
	if rv := context.Get(r, dbContext); rv != nil {
		return rv.(KeyManager)
	}
	return nil
}

func setDB(r *http.Request, val KeyManager) {
	context.Set(r, dbContext, val)
}

// GetRouteID gets the short form function name for the route being called. Used for logging/metrics.
func GetRouteID(r *http.Request) string {
	if rv := context.Get(r, idContext); rv != nil {
		return rv.(string)
	}
	return ""
}

func setRouteID(r *http.Request, val string) {
	context.Set(r, idContext, val)
}

// AddHeader adds a HTTP header to the response
func AddHeader(k, v string) func(http.HandlerFunc) http.HandlerFunc {
	return func(f http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set(k, v)
			f(w, r)
		}
	}
}

// Logger logs the request and response information in json format to the logger given.
func Logger(logger *log.Logger) func(http.HandlerFunc) http.HandlerFunc {
	return func(f http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			f(w, r)
			p := GetPrincipal(r)
			params := GetParams(r)
			apiError := GetAPIError(r)
			agent := r.Header.Get("User-Agent")
			if agent == "" {
				agent = "unknown"
			}
			e := &reqLog{
				Type:       "access",
				StatusCode: 200,
				Request:    buildRequest(r, p, params),
				UserAgent:  agent,
			}
			if apiError != nil {
				e.Code = apiError.Subcode
				e.StatusCode = HTTPErrMap[apiError.Subcode].Code
				e.Msg = apiError.Message
			}
			logger.OutputJSON(e)
		}
	}
}

type reqLog struct {
	Type       string  `json:"type"`
	Code       int     `json:"code"`
	StatusCode int     `json:"status_code"`
	Request    request `json:"request"`
	Msg        string  `json:"msg"`
	UserAgent  string  `json:"userAgent"`
}

type request struct {
	Method             string            `json:"method"`
	Path               string            `json:"path"`
	Parameters         map[string]string `json:"parameters"`
	ParsedQuery        map[string]string `json:"parsed_query_string"`
	Principal          string            `json:"principal"`
	AuthType           string            `json:"auth_type"`
	RequestURI         string            `json:"request_uri"`
	RemoteAddr         string            `json:"remote_addr"`
	TLSServer          string            `json:"tls_server"`
	TLSCipher          uint16            `json:"tls_cipher"`
	TLSVersion         uint16            `json:"tls_version"`
	TLSResumed         bool              `json:"tls_resumed"`
	TLSUnique          []byte            `json:"tls_session_id"`
}

func scrub(params map[string]string) map[string]string {
	// Don't log any secret information (cause its secret)
	if _, ok := params["data"]; ok {
		params["data"] = "<DATA>"
	}
	return params
}

func buildRequest(req *http.Request, p knox.Principal, params map[string]string) request {
	params = scrub(params)

	r := request{
		Method:     req.Method,
		Parameters: params,
		RemoteAddr: req.RemoteAddr,
	}
	if qs, ok := params["queryString"]; ok {
		keyMap, _ := url.ParseQuery(qs)
		m := map[string]string{}
		for k := range keyMap {
			for _, v := range keyMap[k] {
				m[k] = v
			}
		}
		r.ParsedQuery = m
	}
	if req.URL != nil {
		r.Path = req.URL.Path
	}
	if p != nil {
		r.Principal = p.GetID()
		r.AuthType = p.Type()
	} else {
		r.Principal = ""
		r.AuthType = ""
	}
	if req.TLS != nil {
		r.TLSServer = req.TLS.ServerName
		r.TLSCipher = req.TLS.CipherSuite
		r.TLSVersion = req.TLS.Version
		r.TLSResumed = req.TLS.DidResume
		r.TLSUnique = req.TLS.TLSUnique
	}
	return r
}

type ProviderType int

const (
	MTLSAuthProviderType ProviderType = iota
	JWTProviderType
	SpiffeAuthProviderType
	NoFoundProviderType
)

// Authentication sets the principal or returns an error if the principal cannot be authenticated.
func Authentication(providers []auth.Provider) func(http.HandlerFunc) http.HandlerFunc {
	return func(f http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			errReturned := fmt.Errorf("no matching authentication providers found")
			providerType := getProvider(r)
			if providerType == NoFoundProviderType {
				writeErr(errF(knox.UnauthenticatedCode, errReturned.Error()))(w, r)
				return
			}

			principal, errAuthenticate := providers[providerType].Authenticate(r)
			if errAuthenticate != nil {
				writeErr(errF(knox.UnauthenticatedCode, errAuthenticate.Error()))(w, r)
				return
			}

			setPrincipal(r, principal)
			f(w, r)
			return
		}
	}
}

func getProvider(r *http.Request) ProviderType {
	// If request contain JWT token, it'll be authorized using that token
	if jwtHeader := r.Header.Get("Authorization"); jwtHeader != "" {
		return JWTProviderType
	}

	if len(r.TLS.PeerCertificates) != 0 {
		// Check whether certificate contains SPIFFE ID
		spiffeURIs, err := auth.GetURINamesFromExtensions(&(r.TLS.PeerCertificates[0]).Extensions)
		if err != nil || len(spiffeURIs) == 0 {
			return MTLSAuthProviderType
		}
		return SpiffeAuthProviderType
	}
	return NoFoundProviderType
}

func parseParams(parameters []Parameter) func(http.HandlerFunc) http.HandlerFunc {
	return func(f http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			var ps = make(map[string]string)
			for _, p := range parameters {
				if s, ok := p.Get(r); ok {
					ps[p.Name()] = s
				}
			}
			setParams(r, ps)
			f(w, r)
		}
	}
}

func setupRoute(id string, m KeyManager) func(http.HandlerFunc) http.HandlerFunc {
	return func(f http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			setDB(r, m)
			setRouteID(r, id)
			f(w, r)
		}
	}
}
