/*
Copyright © The ESO Authors

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

package externalsecret

import (
	"reflect"
	"testing"
)

// TestDiffSecretDataKeys covers the key-level diff used by issue #2498 logging.
// Only key names should be reported — values are intentionally ignored — and
// only removed / value-emptied cases are tracked.
func TestDiffSecretDataKeys(t *testing.T) {
	cases := []struct {
		name        string
		existing    map[string][]byte
		updated     map[string][]byte
		wantRemoved []string
		wantEmptied []string
	}{
		{
			name:     "no change",
			existing: map[string][]byte{"a": []byte("1"), "b": []byte("2")},
			updated:  map[string][]byte{"a": []byte("1"), "b": []byte("2")},
		},
		{
			name:        "key removed",
			existing:    map[string][]byte{"a": []byte("1"), "b": []byte("2")},
			updated:     map[string][]byte{"a": []byte("1")},
			wantRemoved: []string{"b"},
		},
		{
			name:        "multiple keys removed (sorted)",
			existing:    map[string][]byte{"z": []byte("1"), "a": []byte("2"), "m": []byte("3")},
			updated:     map[string][]byte{},
			wantRemoved: []string{"a", "m", "z"},
		},
		{
			name:        "key emptied",
			existing:    map[string][]byte{"a": []byte("not-empty"), "b": []byte("kept")},
			updated:     map[string][]byte{"a": []byte(""), "b": []byte("kept")},
			wantEmptied: []string{"a"},
		},
		{
			name:        "nil value treated as empty",
			existing:    map[string][]byte{"a": []byte("not-empty")},
			updated:     map[string][]byte{"a": nil},
			wantEmptied: []string{"a"},
		},
		{
			name:     "key changed to a different non-empty value is NOT reported",
			existing: map[string][]byte{"a": []byte("v1")},
			updated:  map[string][]byte{"a": []byte("v2")},
		},
		{
			name:     "newly added keys are NOT reported",
			existing: map[string][]byte{"a": []byte("1")},
			updated:  map[string][]byte{"a": []byte("1"), "b": []byte("2")},
		},
		{
			name:        "removed and emptied combined, both sorted",
			existing:    map[string][]byte{"z": []byte("v"), "y": []byte("v"), "x": []byte("v"), "w": []byte("v")},
			updated:     map[string][]byte{"z": []byte(""), "x": []byte("")},
			wantRemoved: []string{"w", "y"},
			wantEmptied: []string{"x", "z"},
		},
		{
			name:     "previously-empty value staying empty is NOT reported as emptied",
			existing: map[string][]byte{"a": []byte("")},
			updated:  map[string][]byte{"a": []byte("")},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotRemoved, gotEmptied := diffSecretDataKeys(tc.existing, tc.updated)
			if !reflect.DeepEqual(gotRemoved, tc.wantRemoved) {
				t.Errorf("removed = %v, want %v", gotRemoved, tc.wantRemoved)
			}
			if !reflect.DeepEqual(gotEmptied, tc.wantEmptied) {
				t.Errorf("emptied = %v, want %v", gotEmptied, tc.wantEmptied)
			}
		})
	}
}
