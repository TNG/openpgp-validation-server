package main

import (
	"html/template"
	"log"
	"net/http"
	"strings"

	"github.com/TNG/gpg-validation-server/validator"
)

var (
	confirmAcceptedResponse = template.Must(template.ParseFiles("./templates/confirmAccepted.gohtml"))
	confirmErrorResponse    = template.Must(template.ParseFiles("./templates/confirmError.gohtml"))
)

func serveNonceConfirmer(address string) error {
	nonceChan := make(chan [validator.NonceLength]byte)
	go func() {
		for {
			nonce := <-nonceChan
			err := validator.ConfirmNonce(nonce, store)
			if err != nil {
				log.Printf("Cannot confirm nonce: %v", err)
			}
		}
	}()
	http.HandleFunc("/confirm/", func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(r.URL.Path, "/")
		nonce, err := validator.NonceFromString(parts[2])
		if err != nil {
			log.Printf("BAD REQUEST from %v to %v: %v\n", r.RemoteAddr, r.RequestURI, err)
			w.WriteHeader(http.StatusBadRequest)
			if err := confirmErrorResponse.Execute(w, struct{}{}); err != nil {
				log.Panicf("Cannot execute template 'error': %v\n", err)
			}
			return
		}

		log.Printf("ACCEPTED from %v to %v\n", r.RemoteAddr, r.RequestURI)
		w.WriteHeader(http.StatusAccepted)
		if err := confirmAcceptedResponse.Execute(w, struct{}{}); err != nil {
			log.Panicf("Cannot execute template 'accepted': %v\n", err)
		}

		nonceChan <- nonce
	})
	return http.ListenAndServe(address, nil)
}
