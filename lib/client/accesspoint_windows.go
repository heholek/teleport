// +build windows

/*
Copyright 2018 Gravitational, Inc.

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

package client

import (
	"github.com/gravitational/teleport/lib/auth"
)

// accessPoint returns a auth.AccessPoint that is directly connected to the
// Auth Server. The Teleport caching auth client is built upon the dir
// backend which requires support for file locking which Teleport does not
// support on Windows at the moment.
func (tc *TeleportClient) accessPoint(clt auth.AccessPoint, proxyHostPort string, clusterName string) (auth.AccessPoint, error) {
	return clt, nil
}
