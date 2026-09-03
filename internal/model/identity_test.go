package model

import "testing"

func TestArtifactIDEncodesSegmentsAndNormalizesSeparators(t *testing.T) {
	got, err := ArtifactID("pay ments", `charts\api values\Chart.yaml`)
	if err != nil {
		t.Fatal(err)
	}
	want := "can://artifact/pay%20ments/charts/api%20values/Chart.yaml"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestArtifactIDUsesUppercaseEscapesAndOnlyUnreservedRawBytes(t *testing.T) {
	got, err := ArtifactID("app+name", "dir/100%#?.yaml")
	if err != nil {
		t.Fatal(err)
	}
	want := "can://artifact/app%2Bname/dir/100%25%23%3F.yaml"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestArtifactIDRejectsTraversal(t *testing.T) {
	for _, path := range []string{"../Chart.yaml", "/tmp/Chart.yaml", `C:\tmp\Chart.yaml`, "charts/../Chart.yaml"} {
		if _, err := ArtifactID("payments", path); err == nil {
			t.Fatalf("accepted %q", path)
		}
	}
}

func TestAnonymousIDIncludesLineAndColumn(t *testing.T) {
	got := AnonymousID("can://iac/payments/helm/chart", "task", 42, 3)
	if got != "can://iac/payments/helm/chart/task@42:3" {
		t.Fatal(got)
	}
}

func TestSemanticAndConfigKeyIDsEncodeEachSegment(t *testing.T) {
	if got, want := SemanticID("payments", "helm", "templates/a b.yaml"), "can://iac/payments/helm/templates%2Fa%20b.yaml"; got != want {
		t.Fatalf("semantic id got %q want %q", got, want)
	}
	if got, want := ConfigKeyID("can://artifact/payments/values.yaml", "image/tag latest"), "can://artifact/payments/values.yaml@key/image%2Ftag%20latest"; got != want {
		t.Fatalf("config key id got %q want %q", got, want)
	}
}
