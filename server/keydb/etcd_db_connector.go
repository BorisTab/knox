package keydb

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/pinterest/knox"
	clientv3 "go.etcd.io/etcd/client/v3"
)

type EtcdConnector struct {
	etcdClient     *clientv3.Client
	contextTimeout time.Duration
}

func NewEtcdConnector(endpoints []string, dialTimeout time.Duration, contextTimeout time.Duration) *EtcdConnector {
	client, err := clientv3.New(clientv3.Config{
		Endpoints:   endpoints,
		DialTimeout: dialTimeout,
	})

	if err != nil {
		log.Fatalf("Error during etcd connector creation: %s", err)
	}

	connector := &EtcdConnector{
		etcdClient:     client,
		contextTimeout: contextTimeout,
	}

	return connector
}

func (connector *EtcdConnector) Close() {
	connector.etcdClient.Close()
}

func (connector *EtcdConnector) Get(id string) (*DBKey, error) {
	ctx, cancel := context.WithTimeout(context.Background(), connector.contextTimeout)
	response, err := connector.etcdClient.Get(ctx, id)
	cancel()

	if err != nil {
		return nil, err
	}

	if response.Count == 0 {
		return nil, knox.ErrKeyIDNotFound
	}

	key, err := jsonStrToDbKey(string(response.Kvs[0].Value))

	if err != nil {
		return nil, err
	}

	key.DBVersion = response.Kvs[0].Version

	return key, nil
}

func (connector *EtcdConnector) GetAll() ([]DBKey, error) {
	ctx, cancel := context.WithTimeout(context.Background(), connector.contextTimeout)
	response, err := connector.etcdClient.Get(ctx, "", clientv3.WithPrefix())
	cancel()

	if err != nil {
		return nil, err
	}

	dbKeys := make([]DBKey, len(response.Kvs))

	for i, kv := range response.Kvs {
		key, err := jsonStrToDbKey(string(kv.Value))

		if err != nil {
			return nil, err
		}

		key.DBVersion = kv.Version

		dbKeys[i] = *key
	}

	return dbKeys, nil
}

func (connector *EtcdConnector) Update(key *DBKey) error {
	keyError := connector.checkExistenceAndVersion(key)

	if keyError != nil {
		return keyError
	}

	return connector.put(key)
}

func (connector *EtcdConnector) Add(keys ...*DBKey) error {
	for _, key := range keys {
		if connector.isExist(key.ID) {
			return knox.ErrKeyExists
		}

		err := connector.put(key)

		if err != nil {
			return err
		}
	}

	return nil
}

func (connector *EtcdConnector) Remove(id string) error {
	ctx, cancel := context.WithTimeout(context.Background(), connector.contextTimeout)
	deleteResp, err := connector.etcdClient.Delete(ctx, id)
	cancel()

	if deleteResp.Deleted == 0 {
		return knox.ErrKeyIDNotFound
	}

	return err
}

func (connector *EtcdConnector) checkExistenceAndVersion(key *DBKey) error {
	keyInDb, err := connector.Get(key.ID)

	if err != nil {
		// return knox.ErrKeyIDNotFound if key does not exist
		return err
	}

	if keyInDb.DBVersion != key.DBVersion {
		return ErrDBVersion
	}

	return nil
}

func (connector *EtcdConnector) isExist(id string) bool {
	_, keyNotFoundErr := connector.Get(id)
	return keyNotFoundErr != knox.ErrKeyIDNotFound
}

func (connector *EtcdConnector) put(key *DBKey) error {
	etcdValue, err := dbKeyToJsonStr(key)

	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), connector.contextTimeout)
	_, err = connector.etcdClient.Put(ctx, string(key.ID), etcdValue)
	cancel()

	return err
}

func dbKeyToJsonStr(key *DBKey) (string, error) {
	jsonKey, err := json.Marshal(key)

	if err != nil {
		return "", err
	}

	return string(jsonKey), nil
}

func jsonStrToDbKey(etcdKey string) (*DBKey, error) {
	dbKey := &DBKey{}
	err := json.Unmarshal([]byte(etcdKey), dbKey)

	return dbKey, err
}
