package storage

import (
	"encoding/hex"
	"github.com/TNG/openpgp-validation-server/gpg"
	"io/ioutil"
	"log"
	"os"
)

// NewFileStore returns a GetSetDeleter that stores values in a /requests subdirectory
func NewFileStore() GetSetDeleter {
	log.Println("Using file store in current directory")
	m := fileStore{
		directory: "./requests",
	}
	err := os.MkdirAll(m.directory, 0700)
	if err != nil {
		panic(err)
	}
	return &m
}

// fileStore provides a filesystem-based GetSetDeleter
type fileStore struct {
	directory string
}

func (s *fileStore) fileName(nonce [nonceLength]byte, suffix string) string {
	return s.directory + "/" + hex.EncodeToString(nonce[:]) + "." + suffix
}

// data returns the raw bytes saved in the file openpgp Entity saved under the given nonce and suffix
func (s *fileStore) getData(nonce [nonceLength]byte, suffix string) []byte {
	fn := s.fileName(nonce, suffix)
	f, err := os.Open(fn)
	if err != nil {
		return nil
	}
	data, err := ioutil.ReadAll(f)
	if err != nil {
		log.Println(err)
		return nil
	}
	err = f.Close()
	if err != nil {
		log.Println(err)
	}
	return data
}

// data returns the raw bytes saved in the file openpgp Entity saved under the given nonce and suffix
func (s *fileStore) setData(nonce [nonceLength]byte, suffix string, data []byte) {
	fn := s.fileName(nonce, suffix)
	f, err := os.Create(fn)
	if err != nil {
		panic(err)
	}
	_, err = f.Write(data)
	if err != nil {
		panic(err)
	}
	err = f.Close()
	if err != nil {
		panic(err)
	}
}

func (s *fileStore) clearData(nonce [nonceLength]byte, suffix string) {
	fn := s.fileName(nonce, suffix)
	err := os.Remove(fn)
	if err != nil {
		log.Println("Clearing data failed: " + err.Error())
	}
}

// Get returns the openpgp Entity saved under the given nonce
func (s *fileStore) Get(nonce [nonceLength]byte) *RequestInfo {
	info := RequestInfo{}

	emailBytes := s.getData(nonce, "email")
	if emailBytes != nil {
		info.Email = string(emailBytes)
	}

	timestampBytes := s.getData(nonce, "timestamp")
	if timestampBytes != nil {
		err := info.Timestamp.UnmarshalText(timestampBytes)
		if err != nil {
			log.Println(err)
		}
	}

	keyBytes := s.getData(nonce, "key")
	if keyBytes != nil {
		var err error
		info.Key, err = gpg.UnmarshalKey(keyBytes)
		if err != nil {
			log.Println(err)
		}
	}
	if info == (RequestInfo{}) {
		return nil
	}
	return &info
}

// Set persists the given openpgp Entity under the given nonce
func (s *fileStore) Set(nonce [nonceLength]byte, requestor RequestInfo) {
	s.setData(nonce, "email", []byte(requestor.Email))
	ts, err := requestor.Timestamp.MarshalText()
	if err != nil {
		panic(err)
	}
	s.setData(nonce, "timestamp", ts)

	if requestor.Key != nil {
		key, err := gpg.MarshalKey(requestor.Key)
		if err != nil {
			panic(err)
		}
		s.setData(nonce, "key", key)
	}
}

// Delete removes the given nonce from the list
func (s *fileStore) Delete(nonce [nonceLength]byte) {
	s.clearData(nonce, "email")
	s.clearData(nonce, "timestamp")
	s.clearData(nonce, "key")
}
