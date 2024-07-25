package main

import (
	"strings"
	"testing"
)

func TestParseNameConformance(t *testing.T) {
	cases := []string{
		"/v2/test/image/manifests/tagtest0",
		"/v2/test/image/tags/list",
	}
	t.Log(cases)
}

func TestParseNameBlobsUploads(t *testing.T) {
	withUploads, err := parseName("/v2/some/long/chained/repo/name/blobs/uploads")
	if err != nil {
		t.Fatal(err)
	}
	expected := "some/long/chained/repo/name"
	if strings.Compare(withUploads, expected) != 0 {
		t.Errorf("want %s, got %s", expected, withUploads)
	}
}

func TestParseNameBlobsDigest(t *testing.T) {
	withDigest, err := parseName("/v2/some/long/chained/repo/name/blobs/sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
	if err != nil {
		t.Fatal(err)
	}
	expected := "some/long/chained/repo/name"
	if strings.Compare(withDigest, expected) != 0 {
		t.Errorf("want %s, got %s", expected, withDigest)
	}
}

func TestParseNameManifests(t *testing.T) {
	withDigest, err := parseName("/v2/test/image/manifests/tagtest0")
	if err != nil {
		t.Fatal(err)
	}
	expected := "test/image"
	if strings.Compare(withDigest, expected) != 0 {
		t.Errorf("want %s, got %s", expected, withDigest)
	}
}

func TestMatchInvalidRef(t *testing.T) {
	m := matches(refRegex, "sha256:totallywrong")
	if m {
		t.Errorf("Wanted false, got true: %s != %s", refRegex, "sha256:totallywrong")
	}
}
