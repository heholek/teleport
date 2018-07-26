// +build !windows

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
	"path/filepath"

	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/backend/dir"
	"github.com/gravitational/teleport/lib/state"

	"github.com/gravitational/trace"

	"github.com/sirupsen/logrus"
)

// accessPoint returns access point based on the cache policy
func (tc *TeleportClient) accessPointWin(clt auth.AccessPoint, proxyHostPort string, clusterName string) (auth.AccessPoint, error) {
	if tc.CachePolicy == nil {
		logrus.Debugf("not using caching access point")
		return clt, nil
	}
	dirPath, err := initKeysDir(tc.KeysDir)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	path := filepath.Join(dirPath, "cache", proxyHostPort, clusterName)

	logrus.Debugf("using caching access point %v", path)
	cacheBackend, err := dir.New(backend.Params{"path": path})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	// make a caching auth client for the auth server:
	return state.NewCachingAuthClient(state.Config{
		SkipPreload:  true,
		AccessPoint:  clt,
		Backend:      cacheBackend,
		CacheMaxTTL:  tc.CachePolicy.CacheTTL,
		NeverExpires: tc.CachePolicy.NeverExpires,
	})
}
