// test
package main

import (
	"testing"
)

func TestExtractDomain(t *testing.T) {
	for _, u := range []string{
		"http://www.google.com",
		"https://www.google.com",
		"www.google.com",
		"http://www.google.com/",
		"http://www1.mmm.xxx.google.com/",
		"http://www.y.google.com/",
		"http://www.google.com/buh/hum",
		"http://www.google.com/?p=1",
		"http://www.google.com/#frag",
		"http://www.google.com/buh?p=1&q=2",
	} {
		d := extractDomain(u)
		if d != "google.com" {
			t.Error(u)
		}
	}
}

func TestPwdhash(t *testing.T) {
	for in, out := range map[string]string{
		"sesame":       "yGg1DXEs",
		"seSAme":       "PEUaZ5RL",
		"se5ame":       "PrvnMuy8",
		"ses@me":       "jDYGye0+",
		"sesameSESAME": "OmbRtntX7YGeCD",
	} {
		pwd := pwdhash("google.com", in)
		if pwd != out {
			t.Error(pwd)
		}
	}
}
