package auth

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	authz_utils "github.com/pavelzhurov/authz-utils"
	"github.com/pavelzhurov/knox"
)

const (
	namespaceFileName = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)

// Provider is used for authenticating requests via the authentication decorator.
type Provider interface {
	Name() string
	Authenticate(token string, r *http.Request) (knox.Principal, error)
	Version() byte
	Type() byte
}

func verifyCertificate(r *http.Request, cas *x509.CertPool,
	timeFunc func() time.Time) (*x509.Certificate, error) {
	certs := r.TLS.PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("auth: No peer certs configured")
	}
	opts := x509.VerifyOptions{
		Roots:         cas,
		CurrentTime:   timeFunc(),
		Intermediates: x509.NewCertPool(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	for _, cert := range certs[1:] {
		opts.Intermediates.AddCert(cert)
	}

	chains, err := certs[0].Verify(opts)
	if err != nil {
		return nil, fmt.Errorf("auth: failed to verify client's certificate: " + err.Error())
	}
	if len(chains) == 0 {
		return nil, fmt.Errorf("auth: No cert chains could be verified")
	}
	return certs[0], nil
}

// NewMTLSAuthProvider initializes a chain of trust with given CA certificates
func NewMTLSAuthProvider(CAs *x509.CertPool) *MTLSAuthProvider {
	return &MTLSAuthProvider{
		CAs:  CAs,
		time: time.Now,
	}
}

type k8s struct {
	*kubernetes.Clientset
	namespace string
}

func NewKubernetesClient() *k8s {
	// Get things set up for watching - we need a valid k8s client
	clientCfg, err := rest.InClusterConfig()
	if err != nil {
		panic("Unable to get our client configuration")
	}

	clientset, err := kubernetes.NewForConfig(clientCfg)
	if err != nil {
		panic("Unable to create our clientset")
	}

	namespace, err := ioutil.ReadFile(namespaceFileName)
	if err != nil {
		panic("Unable to read our namespace")
	}

	return &k8s{
		clientset,
		string(namespace),
	}
}

// MTLSAuthProvider does authentication by verifying TLS certs against a collection of root CAs
type MTLSAuthProvider struct {
	CAs  *x509.CertPool
	time func() time.Time
}

// Version is set to 0 for MTLSAuthProvider
func (p *MTLSAuthProvider) Version() byte {
	return '0'
}

// Name is the name of the provider for logging
func (p *MTLSAuthProvider) Name() string {
	return "mtls"
}

// Type is set to t for MTLSAuthProvider
func (p *MTLSAuthProvider) Type() byte {
	return 't'
}

// Authenticate performs TLS based Authentication for the MTLSAuthProvider
func (p *MTLSAuthProvider) Authenticate(token string, r *http.Request) (knox.Principal, error) {
	cert, err := verifyCertificate(r, p.CAs, p.time)
	if err != nil {
		return nil, err
	}

	// Check the CN matches the token
	err = cert.VerifyHostname(token)
	if err != nil {
		return nil, err
	}

	return NewMachine(token), nil
}

// NewSpiffeAuthProvider initializes a chain of trust with given CA certificates,
// identical to the MTLS provider except the principal is a Spiffe ID instead
// of a hostname and the CN of the cert is ignored.
func NewSpiffeAuthProvider(CAs *x509.CertPool, isDevServer bool, cmName, crtName string) *SpiffeProvider {
	var kubeClient *k8s
	if !isDevServer {
		kubeClient = NewKubernetesClient()
	}
	return &SpiffeProvider{
		isDev:   isDevServer,
		CAs:     CAs,
		time:    time.Now,
		kuber:   kubeClient,
		cmName:  cmName,
		crtName: crtName,
	}
}

// SpiffeProvider does authentication by verifying TLS certs against a collection of root CAs
type SpiffeProvider struct {
	isDev   bool
	CAs     *x509.CertPool
	time    func() time.Time
	kuber   *k8s
	cmName  string
	crtName string
}

// Version is set to 0 for SpiffeProvider
func (p *SpiffeProvider) Version() byte {
	return '0'
}

// Name is the name of the provider for logging
func (p *SpiffeProvider) Name() string {
	return "spiffe"
}

// Type is set to s for SpiffeProvider
func (p *SpiffeProvider) Type() byte {
	return 's'
}

func (p *SpiffeProvider) ReloadCerts() error {
	certPool := x509.NewCertPool()

	spiffeCaRAW, err := p.kuber.CoreV1().ConfigMaps(p.kuber.namespace).Get(context.TODO(), p.cmName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("couldn't get spiffe CA cert from configmap")
	}
	ok := certPool.AppendCertsFromPEM([]byte(spiffeCaRAW.Data[p.crtName]))
	if !ok {
		return fmt.Errorf("couldn't reload spiffe CA cert")
	}
	p.CAs = certPool
	return nil
}

// Authenticate performs TLS based Authentication and extracts the Spiffe URI extension
func (p *SpiffeProvider) Authenticate(token string, r *http.Request) (knox.Principal, error) {
	if !p.isDev {
		err := p.ReloadCerts()
		if err != nil {
			return nil, err
		}
	}

	cert, err := verifyCertificate(r, p.CAs, p.time)
	if err != nil {
		return nil, err
	}

	// Extract the Spiffe URI extension from the certificate
	spiffeURIs, err := GetURINamesFromExtensions(&cert.Extensions)
	if err != nil {
		return nil, err
	}

	return spiffeToPrincipal(spiffeURIs)
}

func spiffeToPrincipal(spiffeURIs []string) (knox.Principal, error) {
	if len(spiffeURIs) == 0 {
		return nil, fmt.Errorf("auth: no spiffe identity in certificate")
	}
	if len(spiffeURIs) > 1 {
		return nil, fmt.Errorf("auth: more than one service identity specified in certificate")
	}
	uri := spiffeURIs[0]
	if !strings.HasPrefix(uri, "spiffe://") {
		return nil, fmt.Errorf("auth: service identity was not a valid SPIFFE ID (bad prefix)")
	}
	splits := strings.SplitN(uri[9:], "/", 2)
	if len(splits) != 2 {
		return nil, fmt.Errorf("auth: service identity was not a valid SPIFFE ID (bad format)")
	}

	return NewService(splits[0], splits[1]), nil
}

// SpiffeFallbackProvider is a SpiffeProvider that uses the same Type byte as the
// MTLSAuthProvider. The use case for this is to allow a client that specifies
// MTLSAuth to also transparently be given Spiffe based access as well. For
// more predictable results, ensure that the MTLSAuthProvider is registered before
// the SpiffeFallbackProvider so that MTLSAuthProvider is always used if it succeeds.
// Note that this is only possible with the SpiffeProvider because there is no use
// of the token from the AuthorizationHeader in this Provider.
type SpiffeFallbackProvider struct {
	SpiffeProvider
}

// NewSpiffeAuthFallbackProvider initializes a chain of trust with given CA certificates,
// identical to the SpiffeProvider except the Type is defined as the MTLSAuthProvider
// Type().
func NewSpiffeAuthFallbackProvider(CAs *x509.CertPool) *SpiffeFallbackProvider {
	return &SpiffeFallbackProvider{
		SpiffeProvider: SpiffeProvider{
			CAs:  CAs,
			time: time.Now,
		},
	}
}

// Name is the name of the provider for logging
func (p *SpiffeFallbackProvider) Name() string {
	return "spiffe-fallback"
}

// Type is set to be identical to the Type of the MTLSAuthProvider
func (s *SpiffeFallbackProvider) Type() byte {
	return (&MTLSAuthProvider{}).Type()
}

// JWT provider implements user authentication through signed JWT tokens
type JWTProvider struct {
	RSAPubKey *rsa.PublicKey
}

// NewJWTProvider initializes JWTProvider
func NewJWTProvider(RSAPubKey string) (*JWTProvider, error) {
	PubKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(RSAPubKey))
	if err != nil {
		return nil, fmt.Errorf("bad rsa public key %v", RSAPubKey)
	}
	return &JWTProvider{
		RSAPubKey: PubKey,
	}, nil
}

// Version is set to 0 for GitHubProvider
func (p *JWTProvider) Version() byte {
	return '0'
}

// Name is the name of the provider for logging
func (p *JWTProvider) Name() string {
	return "jwt"
}

// Type is set to u for JWTProvider since it authenticates users
func (p *JWTProvider) Type() byte {
	return 'u'
}

// Authenticate uses the token to get user data from github.com
func (p *JWTProvider) Authenticate(tokenString string, r *http.Request) (knox.Principal, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validating expected alg:
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		// RSA public key from Keycloak
		return p.RSAPubKey, nil
	})

	if err != nil {
		fmt.Printf("Error while parsing token: %v\nToken: %+v\n", err, token)
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if username, ok := claims["preferred_username"].(string); ok {
			if group, ok := claims["group"].(string); ok {
				return NewUser(username, []string{group}), nil
			} else {
				return NewUser(username, []string{}), nil
			}
		}
	}
	return nil, fmt.Errorf("bad token %+v", token)
}

// IsUser returns true if the principal, or first principal in the case of mux, is a user.
func IsUser(p knox.Principal) bool {
	if mux, ok := p.(knox.PrincipalMux); ok {
		p = mux.Default()
	}
	_, ok := p.(user)
	return ok
}

// IsService returns true if the principal, or first principal in the case of mux, is a service.
func IsService(p knox.Principal) bool {
	if mux, ok := p.(knox.PrincipalMux); ok {
		p = mux.Default()
	}
	_, ok := p.(service)
	return ok
}

type stringSet map[string]struct{}

func (s *stringSet) memberOf(e string) bool {
	_, ok := map[string]struct{}(*s)[e]
	return ok
}

func setFromList(groups []string) *stringSet {
	var t = stringSet(map[string]struct{}{})
	for _, g := range groups {
		t[g] = struct{}{}
	}
	return &t
}

// NewUser creates a user principal with the given auth Provider.
func NewUser(id string, groups []string) knox.Principal {
	return user{id, *setFromList(groups)}
}

// NewMachine creates a machine principal with the given auth Provider.
func NewMachine(id string) knox.Principal {
	return machine(id)
}

// NewService creates a service principal with the given auth Provider.
func NewService(domain string, path string) knox.Principal {
	return service{domain, path}
}

// User represents an LDAP user and the AuthProvider to allow group information
type user struct {
	ID     string
	groups stringSet
}

func (u user) inGroup(g string) bool {
	return u.groups.memberOf(g)
}

func (u user) GetID() string {
	return u.ID
}

// Type returns the underlying type of a principal, for logging/debugging purposes.
func (u user) Type() string {
	return "user"
}

// CanAccess determines if a User can access an object represented by the ACL
// with a certain AccessType. It compares LDAP username and LDAP group.
func (u user) CanAccess(acl knox.ACL, t knox.AccessType) bool {
	for _, a := range acl {
		switch a.Type {
		case knox.User:
			if a.ID == u.ID && a.AccessType.CanAccess(t) {
				return true
			}
		case knox.UserGroup:
			if u.inGroup(a.ID) && a.AccessType.CanAccess(t) {
				return true
			}
		}
	}
	return false
}

func (u user) CanAccessOPA(authenticator *authz_utils.Authenticator, path string, t knox.AccessType, partition string, service string) bool {
	action, err := t.Type()

	if err != nil {
		log.Println("Error: " + err.Error())
		return false
	}

	result, err := authenticator.Authz(partition, service, u.ID, action, path, nil)

	if err != nil {
		log.Println("Authenticator error: " + err.Error())
		return false
	}

	return result
}

// Machine represents a given machine by their hostname.
type machine string

func (m machine) GetID() string {
	return string(m)
}

// Type returns the underlying type of a principal, for logging/debugging purposes.
func (m machine) Type() string {
	return "machine"
}

// CanAccess determines if a Machine can access an object represented by the ACL
// with a certain AccessType. It compares Machine hostname and hostname prefix.
func (m machine) CanAccess(acl knox.ACL, t knox.AccessType) bool {
	for _, a := range acl {
		switch a.Type {
		case knox.Machine:
			if a.ID == string(m) && a.AccessType.CanAccess(t) {
				return true
			}
		case knox.MachinePrefix:
			// TODO(devinlundberg): Investigate security implications of this
			if strings.HasPrefix(string(m), a.ID) && a.AccessType.CanAccess(t) {
				return true
			}
		}
	}
	return false
}

func (m machine) CanAccessOPA(authenticator *authz_utils.Authenticator, path string, t knox.AccessType, partition string, service string) bool {
	action, err := t.Type()

	if err != nil {
		log.Println("Error: " + err.Error())
		return false
	}

	result, err := authenticator.Authz(partition, service, string(m), action, path, nil)

	if err != nil {
		log.Println("Authenticator error: " + err.Error())
		return false
	}

	return result
}

// Service represents a given service from a trust domain
type service struct {
	domain string
	id     string
}

// GetID converts the internal representation into a SPIFFE id
func (s service) GetID() string {
	return "spiffe://" + s.domain + "/" + s.id
}

// Type returns the underlying type of a principal, for logging/debugging purposes.
func (s service) Type() string {
	return "service"
}

// CanAccess determines if a Service can access an object represented by the ACL
// with a certain AccessType. It compares Service id and id prefix.
func (s service) CanAccess(acl knox.ACL, t knox.AccessType) bool {
	for _, a := range acl {
		switch a.Type {
		case knox.Service:
			if a.ID == string(s.GetID()) && a.AccessType.CanAccess(t) {
				return true
			}
		case knox.ServicePrefix:
			if strings.HasPrefix(s.GetID(), a.ID) && a.AccessType.CanAccess(t) {
				return true
			}
		}
	}
	return false
}

func (s service) CanAccessOPA(authenticator *authz_utils.Authenticator, path string, t knox.AccessType, partition string, service string) bool {
	action, err := t.Type()

	if err != nil {
		log.Println("Error: " + err.Error())
		return false
	}

	result, err := authenticator.Authz(partition, service, s.GetID(), action, path, nil)

	if err != nil {
		log.Println("Authenticator error: " + err.Error())
		return false
	}

	return result
}

// type mockHTTPClient struct{}

// func (c *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
// 	resp := &http.Response{}
// 	resp.Proto = "HTTP/1.1"
// 	resp.ProtoMajor = 1
// 	resp.ProtoMinor = 1
// 	a := req.Header.Get("Authorization")
// 	if a == "" || a == "Bearer notvalid" {
// 		resp.StatusCode = 400
// 		resp.Body = ioutil.NopCloser(bytes.NewBuffer(nil))
// 		resp.Status = "400 Unauthorized"

// 		return resp, nil
// 	}
// 	switch req.URL.Path {
// 	case "/user":
// 		data := "{\"login\":\"testuser\"}"
// 		resp.Body = ioutil.NopCloser(bytes.NewBufferString(data))
// 		resp.StatusCode = 200
// 		return resp, nil
// 	case "/user/orgs":
// 		data := "[{\"login\":\"testgroup\"}]"
// 		resp.Body = ioutil.NopCloser(bytes.NewBufferString(data))
// 		resp.StatusCode = 200
// 		return resp, nil
// 	default:
// 		resp.StatusCode = 404
// 		resp.Body = ioutil.NopCloser(bytes.NewBuffer(nil))
// 		resp.Status = "404 Not found"
// 		return resp, nil
// 	}

// }

// MockGitHubProvider returns a mocked out authentication header with a simple mock "server".
// If there exists an authorization header with user token that does not equal 'notvalid', it will log in as 'testuser'.
func MockJWTProvider() *JWTProvider {
	JWTProvider, _ := NewJWTProvider(
		`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc
mwIDAQAB
-----END PUBLIC KEY-----`)
	return JWTProvider
}
