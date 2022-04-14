package main

import (
	crypto_rand "crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"math/big"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/pavelzhurov/knox"
	"github.com/pavelzhurov/knox/log"
	"github.com/pavelzhurov/knox/server"
	"github.com/pavelzhurov/knox/server/auth"
	"github.com/pavelzhurov/knox/server/keydb"

	_ "github.com/go-sql-driver/mysql"
)

const caCertRaw = `-----BEGIN CERTIFICATE-----
MIIFyTCCA7GgAwIBAgICB+MwDQYJKoZIhvcNAQELBQAwdTELMAkGA1UEBhMCVVMx
CTAHBgNVBAgTADEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEbMBkGA1UECRMSR29s
ZGVuIEdhdGUgQnJpZGdlMQ4wDAYDVQQREwU5NDAxNjEWMBQGA1UEChMNQ29tcGFu
eSwgSU5DLjAgFw0xOTExMTAyMzAwMDBaGA8yMTA5MTExMDIzMDAwMFowdTELMAkG
A1UEBhMCVVMxCTAHBgNVBAgTADEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEbMBkG
A1UECRMSR29sZGVuIEdhdGUgQnJpZGdlMQ4wDAYDVQQREwU5NDAxNjEWMBQGA1UE
ChMNQ29tcGFueSwgSU5DLjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
AMbJxtAU0E1Eb13UKWyOl9L/ByccJtD/4kBICgbI+eQlW6U42tqzYXbZCztKbNYq
bUSg70C42Wn4u6n+c/pBFGmQXwFrbfC2rjWhaebIROmjbnh1NKrx+h9yi3npr4NX
Cu6F68NG2Cgh9jygwnPyhpp/QpBc2Gg1IQcZ8uD7HECrObc6/seVzWiVXCvW71zS
Kort509UX8PNVHCkstK9AJj9qoNVxvQW7/I6iTlPGwjBwXrjfQ2PFLOJaA2wAL7B
6yqfN5qdwyISe9sp1ynnR/iBjdCYI6O2LHpZfGhVVmFzmonpU8EgYehrm5/2wauV
hbK8GtBSFD+YqfmZprxL1Gr8kIzy399+z4Qoj/2U2ULxNG2jn/y/D8CCAEoNSRaY
9l1vD9KqyZJH7r87tAKLcZZcBoEpOi1mrKLvi90PQynn2pO3TnC4bR1dKGMvx2Os
b4EGbaJx0bvOU8il/d3gNy8jnPNqNuJD220YjS33OruSX900b5f/ziEwSY48PFV5
sGTSq9wkHi9ZyXZuvXw9PGiopZ3RdP50IEUz/+1P4iG0v4qRbAIkOVrb6qMm+XqW
1dVlLk88v85oWkUyc17hZG2jHqVtwI0WGeNuYB8a/KieQhff44oPySXnWmmFVdhh
k6w+I07IRe1iplxgU2tvc037AAjhUTgDGgesnuSOjv5NAgMBAAGjYTBfMA4GA1Ud
DwEB/wQEAwIChDAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDwYDVR0T
AQH/BAUwAwEB/zAdBgNVHQ4EFgQUbLOqSkTXCfVItVdpV9SCyOY1B4QwDQYJKoZI
hvcNAQELBQADggIBACCOF8l8zPzuJoCLCIsioHtCFxkRAZEqVMV7BWCfTOglK3G4
8RhMCiwbDTusvUTC1SjRPvSQ9cKUz7KODrSgbN0Ij0X09QxX8ioYlMmyuBYp//yF
3Dd/57ndePvJZk2j0tyJ16bz51b7JXmBvsEXjoNIjlVbyySJco7bgosoRUn6qwMJ
YCvGVr2AYgVHzXACAaPxLxCnHiuBR/FGQN2CEXZD/J+sa3fJRYF81tfCGgFQ9irE
G4kwosoHh2yZ5ZSva7AGyq5EsAPoQaK3rT6iE18osp8hps5TlsccOdML3e089n+9
uN4OuZ3+oR+CS5oGnvdrs44+3T+hCQF2eh4XBt6I8kVicKvxIEvPxCL0JVK+Ky0/
ts7H+TwdHV0/+MoSkvEzpNSUeE/0xcWKrO/mVii2gQ+ejp8wHKxmPhu7wgi6Djm2
lctjqpfntPr7IHBPF3tDlV7zZsvcvP7WRk/0iYLhySYo14zHgjT8qmerbliMqBaU
cGwX2vZ+ZyMcm36zYWO6kNVz7E+MFgIdbJa2P4LmK6fnufvsw3j40Xbm7fYq44WV
+utq9Dfe/nVTSD+QYOxvSO7+bijlSdB7H2gIKOWE498jQERn6eZirRy73r4WMYTK
M23rDWzaOs0LcX0Au4DcxVSnCi8w7VzffwwgbHm93fdbyKqkGxkvofHFCe4q
-----END CERTIFICATE-----`
const caKeyRaw = `-----BEGIN RSA PRIVATE KEY-----
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
FD9zAoIBAQDHwqvl4Y3ED+QIC56i2oAOUdsQdbdNFOA0lOLWEPTXEO/cWOJzf13L
gDTxGUprSv/1U1pjywbNIOeJem2j7rN522aTHlcWPy2ZmQJCXAPSPg9Tf5zPxmge
EOOZ7s7EItia6Jx0ipQBFYK7ttfosJ0rvBD9kul6OgvPt/49UsavlwgvAsddV1Xv
s1yKDTYejlg2GbjaEsjaPJv59QCg5RW5Qsj9Lc2IhCS5rJVvUv89wJP2YQSmunTO
uUXFBVocxGVi0TjN3CJvpMRlhLDdvOuWFg78SWlU+y8rsRXAPAQHnYeTAoz0YXK7
iNvlZApq4JcFo1us4p0XDgV10ZDFOIhxAoIBAAk3bZ+NRpkrLzGKx8NXWgck1+bv
vrqgtZ8yjFHmBq9yjDtQWr/4gwUtiLynPPjh8s3vStlG9adYyZZRbPG4ogWNVD94
d47ybAivTPbLnOHnL3kRDbHFpgCEVCR1w66B5nBx1zLedoTAS4/K4vCjnwLt4Bfb
Tjgt/AzowfehMeiarzTYmfc1NoZwILPY7btLEqT2Lh5gWilu3iRY7sNXKbtsffdD
Ys2YGGIraTIclCbuJID9ryGA1uUgHTw1fbleHFQkAYp9s2/IgbQuHvDGAS7m2lOn
bXW46c6YPi94MqhLSS9mYSMp7ndtqrXL9dzx3E3nUMaS63rocVydtzOFgHE=
-----END RSA PRIVATE KEY-----`

const mtlscaCert = `-----BEGIN CERTIFICATE-----
MIIB5jCCAYygAwIBAgIUD/1LTTQNvk3Rp9399flLlimbgngwCgYIKoZIzj0EAwIw
UTELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRgwFgYDVQQKEw9NeSBDb21wYW55
IE5hbWUxGzAZBgNVBAMTEnVzZU9ubHlJbkRldk9yVGVzdDAeFw0xODAzMDIwMTU5
MDBaFw0yMzAzMDEwMTU5MDBaMFExCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEY
MBYGA1UEChMPTXkgQ29tcGFueSBOYW1lMRswGQYDVQQDExJ1c2VPbmx5SW5EZXZP
clRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARbSovOAo4ZimGBOn+tyftX
+GXShKsy2eFdvX9WfYx2NvYnw+RSM/JjRSBhUsCPXuEh/E5lhwRVfUxIlHry1CkS
o0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU
jjNCAZxA5kjDK1ogrwkdziFiDgkwCgYIKoZIzj0EAwIDSAAwRQIgLXo9amyNn1Y3
qLpqrzVF7N7UQ3mxTl01MvnsqvahI08CIQCArwO8KmbPbN5XZrQ2h9zUgbsebwSG
dfOY505yMqiXig==
-----END CERTIFICATE-----`

var (
	flagAddr = flag.String("http", ":9000", "HTTP port to listen on")
)

const (
	authTimeout = 10 * time.Second // Calls to auth timeout after 10 seconds
	serviceName = "knox_dev"
)

func main() {
	rand.Seed(time.Now().UTC().UnixNano())
	flag.Parse()
	accLogger, errLogger := setupLogging("dev", serviceName)

	dbEncryptionKey := []byte("testtesttesttest")
	cryptor := keydb.NewAESGCMCryptor(0, dbEncryptionKey)

	hostnames_string, ok := os.LookupEnv("KNOX_DNS")
	var hostnames []string
	if ok {
		hostnames = strings.Split(hostnames_string, ",")
	} else {
		hostnames = []string{"localhost:9000"}
	}

	tlsCert, tlsKey, err := buildCert(hostnames)
	if err != nil {
		errLogger.Fatal("Failed to make TLS key or cert: ", err)
	}

	RSAPubKey, ok := os.LookupEnv("RSA_PUBLIC_KEY")
	if !ok {
		errLogger.Fatal("RSA Public Key is not set\n")
	}

	var db keydb.DB
	_, isDevServer := os.LookupEnv("DEV_SERVER")
	var kubeConfig *Config

	if isDevServer {
		db = keydb.NewTempDB()
		// db = keydb.NewEtcdConnector([]string{"localhost:2379", "etcd:2379"}, 5*time.Second, 100*time.Millisecond)
		kubeConfig = &Config{}
	} else {
		kubeConfig, err = ReadKubeConfig()
		if err != nil {
			errLogger.Fatal("Failed to read setting to config from environment variables:", err)
		}

		dbType, ok := os.LookupEnv("DB_TYPE")
		if !ok {
			errLogger.Fatalln("No db type provided")
		}

		switch dbType {
		case "etcd":
			endpointsEnv, ok := os.LookupEnv("ETCD_ENDPOINTS")
			if !ok {
				errLogger.Fatalln("No etcd endpoints provided")
			}

			endpoints := strings.Split(endpointsEnv, ";")

			db = keydb.NewEtcdConnector(endpoints, 5*time.Second, 100*time.Millisecond)

		case "mysql":
		default:
			mysql_password, ok := os.LookupEnv("MYSQL_PASSWORD")
			if !ok {
				errLogger.Fatal("MYSQL_PASSWORD is not set\n")
			}
			d, err := sql.Open("mysql", fmt.Sprintf("root:%v@tcp(mysql)/kms", mysql_password))
			if err != nil {
				errLogger.Fatalf("Can't connect to MYSQL: %v\n", err)
			}
			db, err = keydb.NewSQLDB(d)
			if err != nil {
				errLogger.Fatalf("Can't initialize keyDB: %v\n", err)
			}
		}
	}

	server.AddDefaultAccess(&knox.Access{
		Type:       knox.UserGroup,
		ID:         "security-team",
		AccessType: knox.Admin,
	})

	certPool := x509.NewCertPool()
	if isDevServer {
		certPool.AppendCertsFromPEM([]byte(mtlscaCert))
	} else {
		spiffe_ca_path, ok := os.LookupEnv("SPIFFE_CA_PATH")
		if !ok {
			errLogger.Fatal("SPIFFE CA path is not set")
		}
		spiffe_ca_raw, err := ioutil.ReadFile(spiffe_ca_path)
		if err != nil {
			errLogger.Fatalf("can't read SPIFFE CA %v", err)
		}
		ok = certPool.AppendCertsFromPEM(spiffe_ca_raw)
		if !ok {
			errLogger.Fatal("couldn't add spiffe CA cert")
		}
	}

	JWTProvider, err := auth.NewJWTProvider(RSAPubKey)
	if err != nil {
		errLogger.Fatalf("bad rsa public key %v", RSAPubKey)
	}

	decorators := [](func(http.HandlerFunc) http.HandlerFunc){
		server.Logger(accLogger),
		server.AddHeader("Content-Type", "application/json"),
		server.AddHeader("X-Content-Type-Options", "nosniff"),
		server.Authentication([]auth.Provider{
			auth.NewMTLSAuthProvider(certPool),
			JWTProvider,
			auth.NewSpiffeAuthProvider(certPool, isDevServer, kubeConfig.CMName, kubeConfig.CRTName),
			auth.NewSpiffeAuthFallbackProvider(certPool),
		}),
	}

	r, err := server.GetRouter(cryptor, db, decorators, make([]server.Route, 0))
	if err != nil {
		errLogger.Fatal(err)
	}

	http.Handle("/", r)

	errLogger.Fatal(serveTLS(tlsCert, tlsKey, *flagAddr))
}

func setupLogging(gitSha, service string) (*log.Logger, *log.Logger) {
	accLogger := log.New(os.Stderr, "", 0)
	accLogger.SetVersion(gitSha)
	accLogger.SetService(service)

	errLogger := log.New(os.Stderr, "", 0)
	errLogger.SetVersion(gitSha)
	errLogger.SetService(service)
	return accLogger, errLogger
}

func buildCert(hostnames []string) (certPEMBlock, keyPEMBlock []byte, err error) {
	priv, err := rsa.GenerateKey(crypto_rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(100 * 365 * 24 * time.Hour) // build cert for 100 years
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := crypto_rand.Int(crypto_rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{Organization: []string{"Acme Co"}},
		NotBefore:    notBefore,
		NotAfter:     notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	template.DNSNames = hostnames

	block, _ := pem.Decode([]byte(caCertRaw))
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Printf("%v", err)
	}

	block, _ = pem.Decode([]byte(caKeyRaw))
	caKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		fmt.Printf("%v", err)
	}
	caCert.IsCA = true

	derBytes, err := x509.CreateCertificate(crypto_rand.Reader, &template, caCert, &priv.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	b := x509.MarshalPKCS1PrivateKey(priv)
	// if err != nil {
	// 	return nil, nil, err
	// }

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: b}), nil
}

// serveTLS sets up TLS using Mozilla reccommendations and then serves http
func serveTLS(certPEMBlock, keyPEMBlock []byte, httpPort string) error {
	// This TLS config disables RC4 and SSLv3.
	tlsConfig := &tls.Config{
		NextProtos:               []string{"http/1.1"},
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
		ClientAuth:               tls.RequestClientCert,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
	}

	tlsConfig.Certificates = make([]tls.Certificate, 1)
	var err error
	tlsConfig.Certificates[0], err = tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		return err
	}
	server := &http.Server{Addr: httpPort, Handler: nil, TLSConfig: tlsConfig}

	return server.ListenAndServeTLS("", "")
}
