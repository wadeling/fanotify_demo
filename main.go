package main

import (
	log "github.com/sirupsen/logrus"
	"github.com/wadeling/fanotify_demo/fanotify"
	"time"
)

func main() {
	log.SetLevel(log.DebugLevel)
	log.Info("start")

	_, res := fanotify.NewFileAccessCtrl()
	if !res {
		log.Error("new file access ctrl err")
		return
	}

	// test
	for {
		time.Sleep(10 * time.Second)
	}
}
