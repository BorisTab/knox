module github.com/pavelzhurov/knox

go 1.14

require (
	github.com/caarlos0/env/v6 v6.9.1
	github.com/go-sql-driver/mysql v1.6.0
	github.com/gobwas/glob v0.2.3
	github.com/golang-jwt/jwt v3.2.2+incompatible
	github.com/golang/glog v1.0.0
	github.com/golang/protobuf v1.5.2
	github.com/google/tink/go v1.6.1
	github.com/gorilla/context v1.1.1
	github.com/gorilla/mux v1.8.0
	github.com/pavelzhurov/authz-utils v0.0.0-20220221134701-aac2f9d42c5b // indirect
	github.com/pinterest/knox v0.0.0-20211207222708-13c0858cdca9
	go.etcd.io/etcd/client/v3 v3.5.2
	golang.org/x/crypto v0.0.0-20210817164053-32db794688a5
	gopkg.in/fsnotify.v1 v1.4.7
	k8s.io/apimachinery v0.23.4
	k8s.io/client-go v0.23.4
)
