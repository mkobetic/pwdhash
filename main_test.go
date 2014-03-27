// test
package main

import (
	"testing"
)

func TestExtractDomain(t *testing.T) {
	d := extractDomain("http://www.google.com")
	if d != "google.com" {
		t.Fail()
	}
}

func TestPwdhash(t *testing.T) {
	pwd := pwdhash("google.com", "sesame")
	if pwd != "yGg1DXEs" {
		t.Error(pwd)
	}
}
