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

var (
	flagAddr = flag.String("http", ":9000", "HTTP port to listen on")
)

func main() {
	rand.Seed(time.Now().UTC().UnixNano())
	flag.Parse()

	knoxConfig, err := ReadKnoxConfig()
	if err != nil {
		fmt.Println("Failed to read setting to config from environment variables:", err)
		os.Exit(1)
	}
	hostname := strings.Split(knoxConfig.KnoxHosts[0], ":")[0]
	accLogger, errLogger := setupLogging(knoxConfig.Version, hostname)

	dbEncryptionKey := []byte(knoxConfig.DbEncryptionKey)
	cryptor := keydb.NewAESGCMCryptor(0, dbEncryptionKey)

	tlsCert, tlsKey, err := buildCert(knoxConfig.KnoxHosts)
	if err != nil {
		errLogger.Fatal("Failed to make TLS key or cert: ", err)
	}

	var db keydb.DB

	if knoxConfig.IsDevServer {
		db = keydb.NewTempDB()
		// db = keydb.NewEtcdConnector([]string{"localhost:2379", "etcd:2379"}, 5*time.Second, 100*time.Millisecond)
	} else {
		switch knoxConfig.DbType {
		case "etcd":
			db = keydb.NewEtcdConnector(knoxConfig.EtcdHosts, time.Duration(knoxConfig.EtcdInitTimeout),
				time.Duration(knoxConfig.EtcdDialTimeout), time.Duration(knoxConfig.EtcdContextTimeout))
		case "mysql":
			d, err := sql.Open("mysql", fmt.Sprintf("root:%v@tcp(mysql)/kms", knoxConfig.MySqlPassword))
			if err != nil {
				errLogger.Fatalf("Can't connect to MYSQL: %v\n", err)
			}
			db, err = keydb.NewSQLDB(d)
			if err != nil {
				errLogger.Fatalf("Can't initialize keyDB: %v\n", err)
			}
		default:
			errLogger.Fatal("Uknown DB type")
		}
	}

	server.AddDefaultAccess(&knox.Access{
		Type:       knox.UserGroup,
		ID:         "security-team",
		AccessType: knox.Admin,
	})

	certPool := x509.NewCertPool()
	if knoxConfig.IsDevServer {
		certPool.AppendCertsFromPEM([]byte(mtlscaCert))
	} else {
		certPool.AppendCertsFromPEM([]byte(knoxConfig.SpiffeCA))
	}

	JWTProvider, err := auth.NewJWTProvider(knoxConfig.RSAPubKey)
	if err != nil {
		errLogger.Fatalf("bad rsa public key %v", knoxConfig.RSAPubKey)
	}

	decorators := [](func(http.HandlerFunc) http.HandlerFunc){
		server.Logger(accLogger),
		server.AddHeader("Content-Type", "application/json"),
		server.AddHeader("X-Content-Type-Options", "nosniff"),
		server.Authentication([]auth.Provider{
			auth.NewMTLSAuthProvider(certPool),
			JWTProvider,
			auth.NewSpiffeAuthProvider(certPool, knoxConfig.IsDevServer, knoxConfig.SpiffeCAPath),
			auth.NewSpiffeAuthFallbackProvider(certPool),
		}),
	}

	authzType := server.AclAuthorization
	if knoxConfig.OpaAuthorization {
		authzType = server.OpaAuthorization
	}

	r, err := server.GetRouter(cryptor, db, authzType, decorators, make([]server.Route, 0))
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
