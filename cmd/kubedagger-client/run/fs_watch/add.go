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

package fs_watch

import (
	"io/ioutil"
	"net/http"
	"net/http/httputil"

	"github.com/sirupsen/logrus"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/utils"
)

// SendAddFSWatchRequest sends a request to add a filesystem watch on the target system
func SendAddFSWatchRequest(target string, file string, inContainer bool, active bool) error {
	client := &http.Client{}

	req, err := http.NewRequest("GET", target+"/add_fswatch", nil)
	if err != nil {
		logrus.Fatalln(err)
	}

	req.Header.Set("User-Agent", buildUserAgent(file, inContainer, active))

	b, err := httputil.DumpRequest(req, true)
	logrus.Debugf("\n%s", utils.CleanupHost(string(b)))

	resp, err := client.Do(req)
	if err != nil {
		logrus.Fatalln(err)
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logrus.Fatalln(err)
	}

	logrus.Debugf("\n%s", body)
	return nil
}
