/*
Copyright © 2025 ESO Maintainer Team

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package crd

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	dynfake "k8s.io/client-go/dynamic/fake"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
)

type testPushSecretData struct{}

func (testPushSecretData) GetMetadata() *apiextensionsv1.JSON { return nil }
func (testPushSecretData) GetSecretKey() string               { return "" }
func (testPushSecretData) GetRemoteKey() string               { return "" }
func (testPushSecretData) GetProperty() string                { return "" }

type testPushSecretRemoteRef struct {
	remoteKey string
	property  string
}

func (r testPushSecretRemoteRef) GetRemoteKey() string { return r.remoteKey }
func (r testPushSecretRemoteRef) GetProperty() string  { return r.property }

func makeWhitelistRule(name string, properties ...string) esv1.CRDProviderWhitelistRule {
	return esv1.CRDProviderWhitelistRule{Name: name, Properties: properties}
}

func makeWhitelistRuleNS(namespace, name string, properties ...string) esv1.CRDProviderWhitelistRule {
	return esv1.CRDProviderWhitelistRule{Namespace: namespace, Name: name, Properties: properties}
}

var testResource = esv1.CRDProviderResource{
	Group:   "example.io",
	Version: "v1alpha1",
	Kind:    "Widget",
}

func makeCRDTestStore(rules ...esv1.CRDProviderWhitelistRule) *esv1.CRDProvider {
	store := &esv1.CRDProvider{
		ServiceAccountRef: &esmeta.ServiceAccountSelector{Name: "reader"},
		Resource:          testResource,
	}
	if len(rules) > 0 {
		store.Whitelist = &esv1.CRDProviderWhitelist{Rules: rules}
	}
	return store
}

func makeWidgetObject(name, namespace string, spec map[string]any) *unstructured.Unstructured {
	meta := map[string]any{"name": name}
	if namespace != "" {
		meta["namespace"] = namespace
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "example.io/v1alpha1",
		"kind":       "Widget",
		"metadata":   meta,
		"spec":       spec,
	}}
}

func makeCRDClient(store *esv1.CRDProvider, namespace string, objs ...runtime.Object) *Client {
	return &Client{
		store:      store,
		namespace:  namespace,
		plural:     "widgets",
		namespaced: true,
		storeKind:  esv1.SecretStoreKind,
		dynClient:  dynfake.NewSimpleDynamicClient(runtime.NewScheme(), objs...),
	}
}

// makeCSSClient returns a namespaced ClusterSecretStore client pre-loaded with objs.
func makeCSSClient(store *esv1.CRDProvider, objs ...runtime.Object) *Client {
	return &Client{
		store:      store,
		namespace:  "",
		plural:     "widgets",
		namespaced: true,
		storeKind:  esv1.ClusterSecretStoreKind,
		dynClient:  dynfake.NewSimpleDynamicClient(runtime.NewScheme(), objs...),
	}
}

func TestClientBuildGVR(t *testing.T) {
	c := &Client{store: makeCRDTestStore(), plural: "widgets", namespaced: true, storeKind: esv1.SecretStoreKind}
	gvr := c.buildGVR()
	if gvr.Group != testResource.Group || gvr.Version != testResource.Version || gvr.Resource != "widgets" {
		t.Fatalf("unexpected GVR: %+v", gvr)
	}
}

func TestClientGetSecretClusterScoped(t *testing.T) {
	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "test.external-secrets.io/v1alpha1",
		"kind":       "ClusterDBSpec",
		"metadata": map[string]any{
			"name": "clusterdbspec-sample",
		},
		"spec": map[string]any{
			"password": "cluster-secret",
		},
	}}
	store := &esv1.CRDProvider{
		ServiceAccountRef: &esmeta.ServiceAccountSelector{Name: "reader"},
		Resource: esv1.CRDProviderResource{
			Group:   "test.external-secrets.io",
			Version: "v1alpha1",
			Kind:    "ClusterDBSpec",
		},
	}
	// ExternalSecret lives in default; cluster-scoped Get must not use that namespace.
	c := &Client{
		store:      store,
		namespace:  "default",
		plural:     "clusterdbspecs",
		namespaced: false,
		storeKind:  esv1.ClusterSecretStoreKind,
		dynClient:  dynfake.NewSimpleDynamicClient(runtime.NewScheme(), obj),
	}
	got, err := c.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{
		Key:      "clusterdbspec-sample",
		Property: "spec.password",
	})
	if err != nil {
		t.Fatalf("GetSecret() unexpected error: %v", err)
	}
	if string(got) != "cluster-secret" {
		t.Fatalf("GetSecret() = %q, want %q", string(got), "cluster-secret")
	}
}

func TestExtractValue(t *testing.T) {
	obj := makeWidgetObject("sample", "default", map[string]any{
		"password": "s3cr3t",
		"meta":     map[string]any{"a": "b"},
		"targets": []any{
			map[string]any{"name": "app", "value": "v1"},
			map[string]any{"name": "db", "value": "v2"},
		},
	})

	tests := []struct {
		name       string
		property   string
		fields     []string
		wantStr    string
		wantErrMsg string
		checkFn    func(*testing.T, []byte)
	}{
		{name: "extract by property", property: "spec.password", wantStr: "s3cr3t"},
		{name: "missing property", property: "spec.missing", wantErrMsg: "not found"},
		{name: "invalid JMESPath", property: "spec.targets[?name=='db'", wantErrMsg: "invalid property expression"},
		{name: "JMESPath array expression", property: "spec.targets[?name=='db'].value | [0]", wantStr: "v2"},
		{
			name:   "extract selected fields",
			fields: []string{"spec.password", "spec.meta.a"},
			checkFn: func(t *testing.T, b []byte) {
				var m map[string]any
				if err := json.Unmarshal(b, &m); err != nil {
					t.Fatalf("unmarshal: %v", err)
				}
				if m["spec.password"] != "s3cr3t" {
					t.Fatalf("spec.password = %v", m["spec.password"])
				}
				if m["spec.meta.a"] != "b" {
					t.Fatalf("spec.meta.a = %v", m["spec.meta.a"])
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractValue(obj, tt.property, tt.fields)
			if tt.wantErrMsg != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrMsg) {
					t.Fatalf("extractValue() error = %v, want %q", err, tt.wantErrMsg)
				}
				return
			}
			if err != nil {
				t.Fatalf("extractValue() unexpected error: %v", err)
			}
			if tt.wantStr != "" && string(got) != tt.wantStr {
				t.Fatalf("extractValue() = %q, want %q", string(got), tt.wantStr)
			}
			if tt.checkFn != nil {
				tt.checkFn(t, got)
			}
		})
	}
}

func TestJSONBytesToMap(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		checkFn func(*testing.T, map[string][]byte)
	}{
		{
			name: "object with mixed value types",
			raw:  `{"a":"x","b":1}`,
			checkFn: func(t *testing.T, got map[string][]byte) {
				if string(got["a"]) != "x" {
					t.Fatalf(`["a"] = %q, want "x"`, string(got["a"]))
				}
				if string(got["b"]) != "1" {
					t.Fatalf(`["b"] = %q, want "1"`, string(got["b"]))
				}
			},
		},
		{
			name: "non-object falls back to value key",
			raw:  `"hello"`,
			checkFn: func(t *testing.T, got map[string][]byte) {
				if string(got["value"]) != `"hello"` {
					t.Fatalf(`["value"] = %q, want '"hello"'`, string(got["value"]))
				}
			},
		},
		{
			name: "nested object preserved as JSON",
			raw:  `{"user":"admin","foo":{"bar":42,"baz":"hello"}}`,
			checkFn: func(t *testing.T, got map[string][]byte) {
				if string(got["user"]) != "admin" {
					t.Fatalf(`["user"] = %q, want "admin"`, string(got["user"]))
				}
				var foo map[string]any
				if err := json.Unmarshal(got["foo"], &foo); err != nil {
					t.Fatalf("unmarshal foo: %v", err)
				}
				if foo["bar"] != float64(42) || foo["baz"] != "hello" {
					t.Fatalf("foo = %v, want {bar:42, baz:hello}", foo)
				}
			},
		},
		{
			name: "array value preserved as JSON",
			raw:  `{"items":[{"key":"a","val":"1"},{"key":"b","val":"2"}]}`,
			checkFn: func(t *testing.T, got map[string][]byte) {
				var items []map[string]any
				if err := json.Unmarshal(got["items"], &items); err != nil {
					t.Fatalf("unmarshal items: %v", err)
				}
				if len(items) != 2 || items[0]["key"] != "a" || items[0]["val"] != "1" {
					t.Fatalf("items = %v", items)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := jsonBytesToMap([]byte(tt.raw))
			if err != nil {
				t.Fatalf("jsonBytesToMap() unexpected error: %v", err)
			}
			tt.checkFn(t, got)
		})
	}
}

func TestClientGetSecret(t *testing.T) {
	obj := makeWidgetObject("item-a", "ns1", map[string]any{
		"password": "pw1",
		"foo":      map[string]any{"bar": int64(42), "baz": "hello"},
		"nested":   []any{map[string]any{"key": "ep", "val": "db:5432"}, map[string]any{"key": "fqdn", "val": "u:p@db"}},
	})
	c := makeCRDClient(makeCRDTestStore(), "ns1", obj)

	tests := []struct {
		name       string
		ref        esv1.ExternalSecretDataRemoteRef
		wantStr    string
		wantErrIs  error
		wantErrMsg string
		checkFn    func(*testing.T, []byte)
	}{
		{name: "empty key", ref: esv1.ExternalSecretDataRemoteRef{}, wantErrMsg: "must not be empty"},
		{name: "slash in key rejected", ref: esv1.ExternalSecretDataRemoteRef{Key: "other/item-a"}, wantErrMsg: "must not contain '/'"},
		{name: "missing object maps to NoSecretError", ref: esv1.ExternalSecretDataRemoteRef{Key: "does-not-exist"}, wantErrIs: esv1.NoSecretError{}},
		{name: "returns property value", ref: esv1.ExternalSecretDataRemoteRef{Key: "item-a", Property: "spec.password"}, wantStr: "pw1"},
		{name: "nested scalar via dot path", ref: esv1.ExternalSecretDataRemoteRef{Key: "item-a", Property: "spec.foo.bar"}, wantStr: "42"},
		{name: "JMESPath on array", ref: esv1.ExternalSecretDataRemoteRef{Key: "item-a", Property: "spec.nested[?key=='fqdn'].val | [0]"}, wantStr: "u:p@db"},
		{
			name: "nested object returns JSON",
			ref:  esv1.ExternalSecretDataRemoteRef{Key: "item-a", Property: "spec.foo"},
			checkFn: func(t *testing.T, b []byte) {
				var m map[string]any
				if err := json.Unmarshal(b, &m); err != nil {
					t.Fatalf("unmarshal: %v", err)
				}
				if m["bar"] != float64(42) || m["baz"] != "hello" {
					t.Fatalf("spec.foo = %v", m)
				}
			},
		},
		{
			name: "array property returns JSON array",
			ref:  esv1.ExternalSecretDataRemoteRef{Key: "item-a", Property: "spec.nested"},
			checkFn: func(t *testing.T, b []byte) {
				var arr []map[string]any
				if err := json.Unmarshal(b, &arr); err != nil {
					t.Fatalf("unmarshal: %v", err)
				}
				if len(arr) != 2 || arr[0]["key"] != "ep" {
					t.Fatalf("spec.nested = %v", arr)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := c.GetSecret(context.Background(), tt.ref)
			switch {
			case tt.wantErrMsg != "":
				if err == nil || !strings.Contains(err.Error(), tt.wantErrMsg) {
					t.Fatalf("GetSecret() error = %v, want %q", err, tt.wantErrMsg)
				}
			case tt.wantErrIs != nil:
				if !errors.Is(err, tt.wantErrIs) {
					t.Fatalf("GetSecret() error = %v, want %T", err, tt.wantErrIs)
				}
			default:
				if err != nil {
					t.Fatalf("GetSecret() unexpected error: %v", err)
				}
				if tt.wantStr != "" && string(got) != tt.wantStr {
					t.Fatalf("GetSecret() = %q, want %q", string(got), tt.wantStr)
				}
				if tt.checkFn != nil {
					tt.checkFn(t, got)
				}
			}
		})
	}
}

func TestClientGetSecretClusterSecretStoreNamespacedKey(t *testing.T) {
	obj := makeWidgetObject("item-a", "ns1", map[string]any{"password": "pw1"})
	c := makeCSSClient(makeCRDTestStore(), obj)

	t.Run("bare object name invalid for namespaced kind", func(t *testing.T) {
		_, err := c.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "item-a"})
		if err == nil || !strings.Contains(err.Error(), "namespace/objectName") {
			t.Fatalf("GetSecret() error = %v, want namespace/objectName requirement", err)
		}
	})

	t.Run("namespace/objectName resolves object", func(t *testing.T) {
		got, err := c.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "ns1/item-a", Property: "spec.password"})
		if err != nil {
			t.Fatalf("GetSecret() unexpected error: %v", err)
		}
		if string(got) != "pw1" {
			t.Fatalf("GetSecret() = %q, want %q", string(got), "pw1")
		}
	})

	t.Run("cluster-scoped rejects slash in key", func(t *testing.T) {
		clusterObj := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "example.io/v1alpha1",
			"kind":       "Widget",
			"metadata":   map[string]any{"name": "global"},
			"spec":       map[string]any{"password": "x"},
		}}
		cc := &Client{
			store:      makeCRDTestStore(),
			namespace:  "default",
			plural:     "widgets",
			namespaced: false,
			storeKind:  esv1.ClusterSecretStoreKind,
			dynClient:  dynfake.NewSimpleDynamicClient(runtime.NewScheme(), clusterObj),
		}
		_, err := cc.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "ns/global", Property: "spec.password"})
		if err == nil || !strings.Contains(err.Error(), "does not allow '/'") {
			t.Fatalf("GetSecret() error = %v, want cluster-scoped slash rejection", err)
		}
	})
}

func TestClientGetSecretMap(t *testing.T) {
	obj := makeWidgetObject("item-a", "ns1", map[string]any{
		"map":    map[string]any{"a": "x", "b": int64(1)},
		"foo":    map[string]any{"bar": int64(42), "baz": "hello"},
		"nested": []any{map[string]any{"key": "ep", "val": "db:5432"}, map[string]any{"key": "fqdn", "val": "u:p@db"}},
	})
	c := makeCRDClient(makeCRDTestStore(), "ns1", obj)

	tests := []struct {
		name    string
		ref     esv1.ExternalSecretDataRemoteRef
		checkFn func(*testing.T, map[string][]byte)
	}{
		{
			name: "flat sub-object",
			ref:  esv1.ExternalSecretDataRemoteRef{Key: "item-a", Property: "spec.map"},
			checkFn: func(t *testing.T, got map[string][]byte) {
				if string(got["a"]) != "x" || string(got["b"]) != "1" {
					t.Fatalf("got = %v, want {a:x, b:1}", got)
				}
			},
		},
		{
			name: "spec returns nested objects as JSON",
			ref:  esv1.ExternalSecretDataRemoteRef{Key: "item-a", Property: "spec"},
			checkFn: func(t *testing.T, got map[string][]byte) {
				var foo map[string]any
				if err := json.Unmarshal(got["foo"], &foo); err != nil {
					t.Fatalf("unmarshal foo: %v", err)
				}
				if foo["bar"] != float64(42) || foo["baz"] != "hello" {
					t.Fatalf("foo = %v", foo)
				}
				var nested []map[string]any
				if err := json.Unmarshal(got["nested"], &nested); err != nil {
					t.Fatalf("unmarshal nested: %v", err)
				}
				if len(nested) != 2 || nested[0]["key"] != "ep" {
					t.Fatalf("nested = %v", nested)
				}
			},
		},
		{
			name: "spec.foo returns nested object as flat map",
			ref:  esv1.ExternalSecretDataRemoteRef{Key: "item-a", Property: "spec.foo"},
			checkFn: func(t *testing.T, got map[string][]byte) {
				if string(got["bar"]) != "42" || string(got["baz"]) != "hello" {
					t.Fatalf("got = %v, want {bar:42, baz:hello}", got)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := c.GetSecretMap(context.Background(), tt.ref)
			if err != nil {
				t.Fatalf("GetSecretMap() unexpected error: %v", err)
			}
			tt.checkFn(t, got)
		})
	}
}

func TestClientGetAllSecrets(t *testing.T) {
	objA := makeWidgetObject("app-a", "ns1", map[string]any{"password": "a"})
	objB := makeWidgetObject("sys-b", "ns1", map[string]any{"password": "b"})

	tests := []struct {
		name       string
		client     func() *Client
		find       esv1.ExternalSecretFind
		wantKeys   []string
		wantErrMsg string
	}{
		{
			name:     "no filter returns all",
			client:   func() *Client { return makeCRDClient(makeCRDTestStore(), "ns1", objA, objB) },
			wantKeys: []string{"app-a", "sys-b"},
		},
		{
			name:     "regexp filters list",
			client:   func() *Client { return makeCRDClient(makeCRDTestStore(), "ns1", objA, objB) },
			find:     esv1.ExternalSecretFind{Name: &esv1.FindName{RegExp: "^sys-.*$"}},
			wantKeys: []string{"sys-b"},
		},
		{
			name:       "invalid regex returns error",
			client:     func() *Client { return makeCRDClient(makeCRDTestStore(), "ns1", objA) },
			find:       esv1.ExternalSecretFind{Name: &esv1.FindName{RegExp: "("}},
			wantErrMsg: "invalid name pattern",
		},
		{
			name: "whitelist name rule filters list",
			client: func() *Client {
				return makeCRDClient(makeCRDTestStore(makeWhitelistRule("^app-.*$")), "ns1", objA, objB)
			},
			wantKeys: []string{"app-a"},
		},
		{
			name: "ClusterSecretStore namespaced kind uses namespace/name keys",
			client: func() *Client {
				return makeCSSClient(makeCRDTestStore(),
					makeWidgetObject("app-a", "ns1", map[string]any{"password": "a"}),
					makeWidgetObject("sys-b", "ns2", map[string]any{"password": "b"}),
				)
			},
			wantKeys: []string{"ns1/app-a", "ns2/sys-b"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.client().GetAllSecrets(context.Background(), tt.find)
			if tt.wantErrMsg != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrMsg) {
					t.Fatalf("GetAllSecrets() error = %v, want %q", err, tt.wantErrMsg)
				}
				return
			}
			if err != nil {
				t.Fatalf("GetAllSecrets() unexpected error: %v", err)
			}
			if len(got) != len(tt.wantKeys) {
				t.Fatalf("GetAllSecrets() len = %d, want %d; keys: %v", len(got), len(tt.wantKeys), got)
			}
			for _, k := range tt.wantKeys {
				if _, ok := got[k]; !ok {
					t.Fatalf("GetAllSecrets() missing expected key %q", k)
				}
			}
		})
	}
}

func TestClientMiscMethods(t *testing.T) {
	c := makeCRDClient(makeCRDTestStore(), "ns1")
	if err := c.PushSecret(context.Background(), nil, testPushSecretData{}); err == nil {
		t.Fatalf("PushSecret() expected error")
	}
	if err := c.DeleteSecret(context.Background(), testPushSecretRemoteRef{}); err == nil {
		t.Fatalf("DeleteSecret() expected error")
	}
	if got, err := c.Validate(); err != nil || got != esv1.ValidationResultReady {
		t.Fatalf("Validate() = (%v, %v), want (%v, nil)", got, err, esv1.ValidationResultReady)
	}
	if err := c.Close(context.Background()); err != nil {
		t.Fatalf("Close() unexpected error: %v", err)
	}
}

func TestClientSecretExists(t *testing.T) {
	obj := makeWidgetObject("item-a", "ns1", map[string]any{"password": "pw1"})
	c := makeCRDClient(makeCRDTestStore(), "ns1", obj)

	if exists, err := c.SecretExists(context.Background(), testPushSecretRemoteRef{remoteKey: "item-a"}); err != nil || !exists {
		t.Fatalf("SecretExists(item-a) = (%v, %v), want (true, nil)", exists, err)
	}
	if exists, err := c.SecretExists(context.Background(), testPushSecretRemoteRef{remoteKey: "missing"}); err != nil || exists {
		t.Fatalf("SecretExists(missing) = (%v, %v), want (false, nil)", exists, err)
	}
}

func TestWhitelistMatching(t *testing.T) {
	obj := makeWidgetObject("item-a", "ns1", map[string]any{"password": "pw1"})

	tests := []struct {
		name       string
		rules      []esv1.CRDProviderWhitelistRule
		ref        esv1.ExternalSecretDataRemoteRef
		wantVal    string
		wantErrMsg string
	}{
		{
			name:       "denied when no rule matches",
			rules:      []esv1.CRDProviderWhitelistRule{makeWhitelistRule("^allowed-.*$")},
			ref:        esv1.ExternalSecretDataRemoteRef{Key: "item-a", Property: "spec.password"},
			wantErrMsg: "denied by whitelist",
		},
		{
			name:    "allowed by name rule only",
			rules:   []esv1.CRDProviderWhitelistRule{makeWhitelistRule("^item-.*$")},
			ref:     esv1.ExternalSecretDataRemoteRef{Key: "item-a", Property: "spec.password"},
			wantVal: "pw1",
		},
		{
			name:       "denied when property does not match rule",
			rules:      []esv1.CRDProviderWhitelistRule{makeWhitelistRule("^item-.*$", "^spec\\.allowed$")},
			ref:        esv1.ExternalSecretDataRemoteRef{Key: "item-a", Property: "spec.password"},
			wantErrMsg: "denied by whitelist",
		},
		{
			name:    "allowed when both name and property match",
			rules:   []esv1.CRDProviderWhitelistRule{makeWhitelistRule("^item-.*$", "^spec\\.password$")},
			ref:     esv1.ExternalSecretDataRemoteRef{Key: "item-a", Property: "spec.password"},
			wantVal: "pw1",
		},
		{
			name: "allowed when name is empty and one of two properties matches",
			rules: []esv1.CRDProviderWhitelistRule{{
				Properties: []string{"^spec\\.username$", "^spec\\.password$"},
			}},
			ref:     esv1.ExternalSecretDataRemoteRef{Key: "item-a", Property: "spec.password"},
			wantVal: "pw1",
		},
		{
			name: "denied when name is empty and none of two properties match",
			rules: []esv1.CRDProviderWhitelistRule{{
				Properties: []string{"^spec\\.username$", "^spec\\.token$"},
			}},
			ref:        esv1.ExternalSecretDataRemoteRef{Key: "item-a", Property: "spec.password"},
			wantErrMsg: "denied by whitelist",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := makeCRDClient(makeCRDTestStore(tt.rules...), "ns1", obj)
			got, err := c.GetSecret(context.Background(), tt.ref)
			if tt.wantErrMsg != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrMsg) {
					t.Fatalf("GetSecret() error = %v, want %q", err, tt.wantErrMsg)
				}
				return
			}
			if err != nil {
				t.Fatalf("GetSecret() unexpected error: %v", err)
			}
			if string(got) != tt.wantVal {
				t.Fatalf("GetSecret() = %q, want %q", string(got), tt.wantVal)
			}
		})
	}
}

// TestWhitelistNamespaceField verifies that rule.Namespace is honoured for
// ClusterSecretStore and silently ignored for SecretStore.
func TestWhitelistNamespaceField(t *testing.T) {
	obj := makeWidgetObject("item-a", "ns1", map[string]any{"password": "pw1"})

	nsRef := func(key string) esv1.ExternalSecretDataRemoteRef {
		return esv1.ExternalSecretDataRemoteRef{Key: key, Property: "spec.password"}
	}

	tests := []struct {
		name       string
		makeClient func() *Client
		ref        esv1.ExternalSecretDataRemoteRef
		wantVal    string
		wantErrMsg string
	}{
		{
			name:       "namespace rule allows matching namespace",
			makeClient: func() *Client { return makeCSSClient(makeCRDTestStore(makeWhitelistRuleNS("^ns1$", "")), obj) },
			ref:        nsRef("ns1/item-a"),
			wantVal:    "pw1",
		},
		{
			name:       "namespace rule denies non-matching namespace",
			makeClient: func() *Client { return makeCSSClient(makeCRDTestStore(makeWhitelistRuleNS("^prod$", "")), obj) },
			ref:        nsRef("ns1/item-a"),
			wantErrMsg: "denied by whitelist",
		},
		{
			name:       "namespace regex matches via pattern",
			makeClient: func() *Client { return makeCSSClient(makeCRDTestStore(makeWhitelistRuleNS("^ns.*$", "")), obj) },
			ref:        nsRef("ns1/item-a"),
			wantVal:    "pw1",
		},
		{
			name: "both namespace and name must match",
			makeClient: func() *Client {
				return makeCSSClient(makeCRDTestStore(makeWhitelistRuleNS("^ns1$", "^other-.*$")), obj)
			},
			ref:        nsRef("ns1/item-a"),
			wantErrMsg: "denied by whitelist",
		},
		{
			// SecretStore ignores rule.Namespace entirely; the implicit namespace is the store namespace.
			name:       "SecretStore: namespace rule ignored",
			makeClient: func() *Client { return makeCRDClient(makeCRDTestStore(makeWhitelistRuleNS("^prod$", "")), "ns1", obj) },
			ref:        nsRef("item-a"),
			wantVal:    "pw1",
		},
		{
			name:       "invalid namespace regex returns error",
			makeClient: func() *Client { return makeCSSClient(makeCRDTestStore(makeWhitelistRuleNS("(invalid", "")), obj) },
			ref:        nsRef("ns1/item-a"),
			wantErrMsg: "invalid whitelist namespace regex",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.makeClient().GetSecret(context.Background(), tt.ref)
			if tt.wantErrMsg != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrMsg) {
					t.Fatalf("GetSecret() error = %v, want %q", err, tt.wantErrMsg)
				}
				return
			}
			if err != nil {
				t.Fatalf("GetSecret() unexpected error: %v", err)
			}
			if string(got) != tt.wantVal {
				t.Fatalf("GetSecret() = %q, want %q", string(got), tt.wantVal)
			}
		})
	}
}

// TestWhitelistNamespaceGetAllSecrets verifies namespace whitelist filtering in GetAllSecrets.
func TestWhitelistNamespaceGetAllSecrets(t *testing.T) {
	o1 := makeWidgetObject("app-a", "ns1", map[string]any{"password": "a"})
	o2 := makeWidgetObject("app-b", "ns2", map[string]any{"password": "b"})

	tests := []struct {
		name     string
		rules    []esv1.CRDProviderWhitelistRule
		wantKeys []string
	}{
		{
			name:     "namespace rule allows only matching namespace",
			rules:    []esv1.CRDProviderWhitelistRule{makeWhitelistRuleNS("^ns1$", "")},
			wantKeys: []string{"ns1/app-a"},
		},
		{
			name:     "namespace rule combined with name rule",
			rules:    []esv1.CRDProviderWhitelistRule{makeWhitelistRuleNS("^ns1$", ""), makeWhitelistRuleNS("", "^app-b$")},
			wantKeys: []string{"ns1/app-a", "ns2/app-b"},
		},
		{
			name:     "namespace regex filters to ns2",
			rules:    []esv1.CRDProviderWhitelistRule{makeWhitelistRuleNS("^ns2$", "")},
			wantKeys: []string{"ns2/app-b"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := makeCSSClient(makeCRDTestStore(tt.rules...), o1, o2)
			got, err := c.GetAllSecrets(context.Background(), esv1.ExternalSecretFind{})
			if err != nil {
				t.Fatalf("GetAllSecrets() unexpected error: %v", err)
			}
			if len(got) != len(tt.wantKeys) {
				t.Fatalf("GetAllSecrets() len = %d, want %d; keys: %v", len(got), len(tt.wantKeys), got)
			}
			for _, k := range tt.wantKeys {
				if _, ok := got[k]; !ok {
					t.Fatalf("GetAllSecrets() missing expected key %q; got %v", k, got)
				}
			}
		})
	}
}
