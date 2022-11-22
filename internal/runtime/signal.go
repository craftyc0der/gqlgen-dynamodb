package runtime

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

func SetupSignal(cancel context.CancelFunc) {
	go func() {
		termChan := make(chan os.Signal, 3)
		signal.Notify(termChan, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
		<-termChan
		cancel()
	}()
}
