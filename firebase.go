package main

import (
    "fmt"
    "github.com/zabawaba99/firego"
)

func writeToFirebase(row []string) {
	f := firego.New("https://ccit-matched-data.firebaseio.com/", nil)
    // working...
    // need to hide url and auth key

	fmt.Println(row)
}
