package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/websocket"
	"github.com/pkg/browser"
)

var wsupgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

func wsHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := wsupgrader.Upgrade(w, r, nil)
	if err != nil {
		fmt.Printf("Failed to set websocket upgrade: %+v\n", err)
		return
	}
	for data := range wsCh {
		log.Println(data)
		conn.WriteJSON(data)
	}
}

func serve() {
	browser.OpenURL("http://localhost:5000")
	http.Handle("/", http.FileServer(http.Dir("wwwroot")))
	http.HandleFunc("/ws", wsHandler)
	http.ListenAndServe(":5000", nil)
}
