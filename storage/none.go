package storage

import (
	"log"
)

// NewNoneStore returns a GetSetDeleter that does not store anything
func NewNoneStore() GetSetDeleter {
	log.Println("Using no store: No data will be saved.")
	return nil
}
