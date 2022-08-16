package main

// #include <stdlib.h>
import "C"

import (
	"bytes"
	"runtime"

	core "github.com/v2fly/v2ray-core/v5"

	"github.com/v2fly/v2ray-core/v5/infra/conf/serial"
	"github.com/v2fly/v2ray-core/v5/main/commands"
	"github.com/v2fly/v2ray-core/v5/main/commands/base"
	_ "github.com/v2fly/v2ray-core/v5/main/distro/all"
)

func main() {
	base.RootCommand.Long = "A unified platform for anti-censorship."
	base.RegisterCommand(commands.CmdRun)
	base.RegisterCommand(commands.CmdVersion)
	base.RegisterCommand(commands.CmdTest)
	base.SortLessFunc = runIsTheFirst
	base.SortCommands()
	base.Execute()
}

func runIsTheFirst(i, j *base.Command) bool {
	left := i.Name()
	right := j.Name()
	if left == "run" {
		return true
	}
	if right == "run" {
		return false
	}
	return left < right
}

var v2RayServer core.Server

//export IsStarted
func IsStarted() bool {
	return v2RayServer != nil
}

//export StartWithJsonConfig
func StartWithJsonConfig(jsonConfigStringIntptr *C.char) {

	if v2RayServer == nil {
		jsonConfigString := C.GoString(jsonConfigStringIntptr)

		server, err := startV2Ray(jsonConfigString)
		if err != nil {
			base.Fatalf("Failed to start: %s", err)
		}

		if err := server.Start(); err != nil {
			base.Fatalf("Failed to start: %s", err)
		}

		v2RayServer = server
		//defer server.Close()

		// Explicitly triggering GC to remove garbage from config loading.
		runtime.GC()
		/*
			{
				osSignals := make(chan os.Signal, 1)
				signal.Notify(osSignals, os.Interrupt, syscall.SIGTERM)
				<-osSignals
			}
		*/
	}
}

//export Stop
func Stop() {
	if v2RayServer != nil {
		v2RayServer.Close()
		runtime.GC()
		v2RayServer = nil
	}
}

func startV2Ray(jsonConfigString string) (core.Server, error) {

	data := []byte(jsonConfigString)

	r := bytes.NewReader(data)
	config, err := serial.LoadJSONConfig(r)

	if err != nil {
		return nil, err
	}

	server, err := core.New(config)
	if err != nil {
		return nil, newError("failed to create server").Base(err)
	}

	return server, nil
}
