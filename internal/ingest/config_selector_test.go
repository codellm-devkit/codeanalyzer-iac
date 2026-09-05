package ingest

import "testing"

func TestGraphConfigArtifactIDDecodesRelativeSelectorExactlyOnce(t *testing.T) {
	for _, test := range []struct {
		selector string
		want     string
	}{
		{selector: "configs/my%20profile.yaml", want: "can://artifact/payments/configs/my%20profile.yaml"},
		{selector: "configs/my%2520profile.yaml", want: "can://artifact/payments/configs/my%2520profile.yaml"},
	} {
		t.Run(test.selector, func(t *testing.T) {
			got, err := GraphConfigArtifactID("payments", test.selector)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("GraphConfigArtifactID() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestGraphConfigArtifactIDRejectsDecodedTraversal(t *testing.T) {
	if _, err := GraphConfigArtifactID("payments", "configs/%2e%2e/secret.yaml"); err == nil {
		t.Fatal("encoded traversal was accepted")
	}
	got, err := GraphConfigArtifactID("payments", "configs/%252e%252e/secret.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if got != "can://artifact/payments/configs/%252e%252e/secret.yaml" {
		t.Fatalf("double-encoded path was decoded twice: %q", got)
	}
}
