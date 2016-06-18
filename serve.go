package main

import (
	"fmt"
	"net/http"

	"github.com/gorilla/websocket"
	"github.com/toqueteos/webbrowser"
)

var wsupgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

func serve() {
	webbrowser.Open("http://localhost:5000")
	http.Handle("/", http.FileServer(http.Dir("wwwroot")))
	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := wsupgrader.Upgrade(w, r, nil)
		if err != nil {
			fmt.Printf("Failed to set websocket upgrade: %+v\n", err)
			return
		}
		for data := range wsCh {
			conn.WriteJSON(data)
		}
	})
	http.ListenAndServe(":5000", nil)
}
