package model

import (
	"encoding/json"
	"testing"
)

// FuzzBatch: an ingest body is untrusted. Decoding and validating any input
// must not panic, and every observation of a valid batch must be Usable
// (collectors rely on Usable to drop what Validate would refuse).
func FuzzBatch(f *testing.F) {
	f.Add([]byte(`{"schema_version":"1","collector":{"id":"a"},"asset":{"kind":"host","name":"h","identifiers":[{"scheme":"machine-id","value":"m"}]},"observed_at":"2026-01-01T00:00:00Z","observations":[{"purl":"pkg:npm/a@1"}]}`))
	f.Add([]byte(`{"schema_version":"1","asset":{"kind":"application","identifiers":[{"scheme":"app-path","value":"/x"}]},"relations":[{"kind":"runs_on","to":[]}]}`))
	f.Add([]byte(`{"observations":[{"purl":"pkg:npm/%zz@1","evidence":{"":""}}],"coverage":[{"status":"bogus"}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var b ObservationBatch
		if json.Unmarshal(data, &b) != nil {
			return
		}
		if b.Validate() != nil {
			return
		}
		for _, o := range b.Observations {
			if !Usable(o) {
				t.Fatalf("valid batch with an unusable observation %+v", o)
			}
		}
	})
}
