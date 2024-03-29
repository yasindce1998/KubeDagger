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

package run

import (
	"fmt"
	"os"
	"os/signal"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	kubedagger "github.com/yasindce1998/KubeDagger/pkg/kubedagger"
)

func kubeDaggerCmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)

	kubeDagger := kubedagger.New(options.KUBEDagger)
	if err := kubeDagger.Start(); err != nil {
		return errors.Wrap(err, "couldn't start")
	}

	wait()

	_ = kubeDagger.Stop()
	return nil
}

// wait stops the main goroutine until an interrupt or kill signal is sent
func wait() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)
	<-sig
	fmt.Println()
}
