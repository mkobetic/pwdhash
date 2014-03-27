// pwdhash project main.go
package main

import (
	"bytes"
	"code.google.com/p/gopass"
	"crypto/hmac"
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"strings"
	"unicode"
)

var nonWord, _ = regexp.Compile("\\W")

func main() {
	if len(os.Args) != 2 {
		usage()
		return
	}
	realm := extractDomain(os.Args[1])
	password, _ := gopass.GetPass(fmt.Sprintf("Password for %s: ", realm))
	fmt.Println(pwdhash(realm, password))
}

func usage() {
	fmt.Println("Usage: pwdhash <url>")
	fmt.Println("Example: pwdhash http://www.google.com")
}

func extractDomain(urlString string) string {
	if hasScheme, _ := regexp.MatchString(`https?://.*`, urlString); !hasScheme {
		urlString = "http://" + urlString
	}
	u, err := url.Parse(urlString)
	if err != nil {
		fmt.Println("Provided argument is not a valid URL!")
		os.Exit(1)
	}
	d := strings.Split(strings.Split(u.Host, ":")[0], ".")
	return strings.Join(d[len(d)-2:], ".")
}

func pwdhash(realm, password string) string {
	hmac := hmac.New(md5.New, []byte(password))
	io.WriteString(hmac, realm)
	hash := base64.StdEncoding.EncodeToString(hmac.Sum(nil))
	size := len(password) + 2
	nonalphanumeric := nonWord.FindStringIndex(password) != nil
	return applyConstraints(hash, size, nonalphanumeric)
}

func applyConstraints(hash string, size int, nonalphanumeric bool) string {
	startingSize := size - 4
	result := make([]byte, startingSize, size)
	copy(result, hash[:startingSize])
	extras := []byte(hash[startingSize:])
	next := extras[0]
	extras = extras[1:]
	if bytes.IndexFunc(result, unicode.IsUpper) < 0 {
		next = 'A' + next%26
	}
	result = append(result, next)
	next = extras[0]
	extras = extras[1:]
	if bytes.IndexFunc(result, unicode.IsLower) < 0 {
		next = 'a' + next%26
	}
	result = append(result, next)
	next = extras[0]
	extras = extras[1:]
	if bytes.IndexFunc(result, unicode.IsDigit) < 0 {
		next = '0' + next%10
	}
	result = append(result, next)
	if !nonalphanumeric || nonWord.FindIndex(result) == nil {
		next = '+'
	} else {
		next = extras[0]
		extras = extras[1:]
	}
	result = append(result, next)

	if !nonalphanumeric {
		loc := nonWord.FindIndex(result)
		for ; loc != nil; loc = nonWord.FindIndex(result) {
			next = extras[0]
			extras = extras[1:]
			result[loc[0]] = 'A' + next%26
		}
	}
	next = extras[0] % byte(len(result))
	rotated := append(result[next:], result[:next]...)
	return string(rotated)
}
