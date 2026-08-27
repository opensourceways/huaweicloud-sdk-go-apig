/*
 *  Copyright (c) Huawei Technologies Co., Ltd. 2017-2025. All rights reserved.
 */

package core

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"net/http"
	"net/textproto"
	"sort"
	"strings"
	"time"

	"github.com/emmansun/gmsm/sm3"
)

const (
	BasicDateFormat     = "20060102T150405Z"
	HeaderXDate         = "X-Sdk-Date"
	HeaderHost          = "host"
	HeaderAuthorization = "Authorization"
	HeaderContentSha256 = "X-Sdk-Content-Sha256"
	DefaultAlgorithm    = "SDK-HMAC-SHA256"
	EmptyString         = ""
	SignedHeadersPrefix = "SignedHeaders="
	V11                 = "V11"
	SdkHmacSha256       = "SDK-HMAC-SHA256"
	V11HmacSha256       = "V11-HMAC-SHA256"
	SdkHmacSm3          = "SDK-HMAC-SM3"
	V11HmacSm3          = "V11-HMAC-SM3"
)

var sha256AlgSet = map[string]struct{}{
	"SDK-HMAC-SHA256": {},
	"V11-HMAC-SHA256": {},
}
var sm3AlgSet = map[string]struct{}{
	"SDK-HMAC-SM3": {},
	"V11-HMAC-SM3": {},
}

// CanonicalRequest Build a canonicalRequest from a regular request string
func CanonicalRequest(request *http.Request, signedHeaders []string, hashFunc hash.Hash) (string, error) {
	var hexencode string
	var err error
	if hex := request.Header.Get(HeaderContentSha256); hex != "" {
		hexencode = hex
	} else {
		bodyData, err := RequestPayload(request)
		if err != nil {
			return "", err
		}
		hexencode, err = HexEncodeSHA256Hash(bodyData, hashFunc)
		if err != nil {
			return "", err
		}
	}
	return fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s", request.Method, CanonicalURI(request),
		CanonicalQueryString(request), CanonicalHeaders(request, signedHeaders),
		strings.Join(signedHeaders, ";"), hexencode), err
}

// CanonicalURI returns request uri
func CanonicalURI(request *http.Request) string {
	pattens := strings.Split(request.URL.Path, "/")
	var uriSlice []string
	for _, v := range pattens {
		uriSlice = append(uriSlice, escape(v))
	}
	urlpath := strings.Join(uriSlice, "/")
	if len(urlpath) == 0 || urlpath[len(urlpath)-1] != '/' {
		urlpath = urlpath + "/"
	}
	return urlpath
}

// CanonicalQueryString
func CanonicalQueryString(request *http.Request) string {
	var keys []string
	queryMap := request.URL.Query()
	for key := range queryMap {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var query []string
	for _, key := range keys {
		k := escape(key)
		sort.Strings(queryMap[key])
		for _, v := range queryMap[key] {
			kv := fmt.Sprintf("%s=%s", k, escape(v))
			query = append(query, kv)
		}
	}
	queryStr := strings.Join(query, "&")
	request.URL.RawQuery = queryStr
	return queryStr
}

// CanonicalHeaders
func CanonicalHeaders(request *http.Request, signerHeaders []string) string {
	var canonicalHeaders []string
	header := make(map[string][]string)
	for k, v := range request.Header {
		header[strings.ToLower(k)] = v
	}
	for _, key := range signerHeaders {
		value := header[key]
		if strings.EqualFold(key, HeaderHost) {
			value = []string{request.Host}
		}
		sort.Strings(value)
		for _, v := range value {
			canonicalHeaders = append(canonicalHeaders, key+":"+strings.TrimSpace(v))
		}
	}
	return fmt.Sprintf("%s\n", strings.Join(canonicalHeaders, "\n"))
}

// SignedHeaders
func SignedHeaders(r *http.Request) []string {
	var signedHeaders []string
	for key := range r.Header {
		signedHeaders = append(signedHeaders, strings.ToLower(key))
	}
	sort.Strings(signedHeaders)
	return signedHeaders
}

// RequestPayload Obtains the request body content.
func RequestPayload(request *http.Request) ([]byte, error) {
	if request.Body == nil {
		return []byte(""), nil
	}
	bodyByte, err := ioutil.ReadAll(request.Body)
	if err != nil {
		return []byte(""), err
	}
	request.Body = ioutil.NopCloser(bytes.NewBuffer(bodyByte))
	return bodyByte, err
}

// HexEncodeSHA256Hash returns hexcode of sha256
func HexEncodeSHA256Hash(body []byte, hashFunc hash.Hash) (string, error) {
	if len(body) == 0 {
		body = []byte("")
	}
	hashInstance := hashFunc
	_, err := hashInstance.Write(body)
	return fmt.Sprintf("%x", hashInstance.Sum(nil)), err
}

// Signature HWS meta
type Signer struct {
	Key              string
	Secret           string
	CustomAuthHeader string
	Algorithm        string
	RegionId         string
	HashFunc         func() hash.Hash
}

// StringToSign Create a "String to Sign".
func (s *Signer) StringToSign(canonicalRequest string, t time.Time) (string, error) {
	hashStruct := s.HashFunc()
	_, err := hashStruct.Write([]byte(canonicalRequest))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s\n%s\n%x",
		s.Algorithm, t.UTC().Format(BasicDateFormat), hashStruct.Sum(nil)), nil
}

func (s *Signer) SignStringToSign(stringToSign string, signingKey []byte) (string, error) {
	hm := hmac.New(s.HashFunc, signingKey)
	_, err := hm.Write([]byte(stringToSign))
	if err != nil {
		return "", err
	}
	res := hm.Sum(nil)
	return fmt.Sprintf("%x", res), nil
}

// AuthHeaderValue Get the finalized value for the "Authorization" header. The signature parameter is the output from SignStringToSign
func (s *Signer) AuthHeaderValue(signatureStr, accessKeyStr string, signedHeaders []string) string {
	return fmt.Sprintf("%s Access=%s, SignedHeaders=%s, Signature=%s", s.Algorithm, accessKeyStr,
		strings.Join(signedHeaders, ";"), signatureStr)
}

func (s *Signer) setSigner() error {
	var hashFunc func() hash.Hash
	if s.Algorithm == "" {
		s.Algorithm = DefaultAlgorithm
	}
	algorithm := strings.ToUpper(s.Algorithm)
	if _, exists := sha256AlgSet[algorithm]; exists {
		hashFunc = sha256.New
	} else if _, exists = sm3AlgSet[algorithm]; exists {
		hashFunc = sm3.New
	} else {
		return errors.New("unsupported algorithm")
	}
	s.HashFunc = hashFunc
	if strings.HasPrefix(algorithm, V11) && len(s.RegionId) == 0 {
		return errors.New("regionId cannot be empty when using the V11 algorithm")
	}
	return nil
}

// Sign SignRequest set Authorization header
func (s *Signer) Sign(request *http.Request) error {
	err := s.setSigner()
	if err != nil {
		return err
	}
	authValueStr, err := s.getAuthValueStr(request)
	if err != nil {
		return err
	}

	if s.CustomAuthHeader != "" {
		request.Header.Set(s.CustomAuthHeader, authValueStr)
	} else {
		request.Header.Set(HeaderAuthorization, authValueStr)
	}
	return nil
}

func (s *Signer) getAuthValueStr(request *http.Request) (string, error) {
	var (
		t    time.Time
		date string
		err  error
	)
	if date = request.Header.Get(HeaderXDate); date != "" {
		t, err = time.Parse(BasicDateFormat, date)
	}
	if err != nil || date == "" {
		t = time.Now()
		request.Header.Set(HeaderXDate, t.UTC().Format(BasicDateFormat))
	}
	signedHeaders := SignedHeaders(request)
	canonicalRequest, err := CanonicalRequest(request, signedHeaders, s.HashFunc())
	if err != nil {
		return "", err
	}

	var authValueStr string
	if strings.HasPrefix(s.Algorithm, V11) {
		v11Sign := signV11{
			signer: s,
		}
		authValueStr, err = v11Sign.generateAuth(canonicalRequest, t, signedHeaders)
		if err != nil {
			return "", err
		}
	} else {
		var stringToSignStr, signatureStr string
		stringToSignStr, err = s.StringToSign(canonicalRequest, t)
		if err != nil {
			return "", err
		}
		signatureStr, err = s.SignStringToSign(stringToSignStr, []byte(s.Secret))
		if err != nil {
			return "", err
		}
		authValueStr = s.AuthHeaderValue(signatureStr, s.Key, signedHeaders)
	}
	return authValueStr, nil
}

// Verify Signature Verification
func (s *Signer) Verify(request *http.Request, authorization string) (bool, error) {
	requestCopy := request.Clone(request.Context())
	if requestCopy == nil {
		return false, errors.New("clone request fail")
	}

	if request.Body != nil {
		defer request.Body.Close()
		bodyBytes, err := io.ReadAll(request.Body)
		if err != nil {
			return false, err
		}
		request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		requestCopy.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}

	if s.CustomAuthHeader != "" {
		delete(requestCopy.Header, textproto.CanonicalMIMEHeaderKey(s.CustomAuthHeader))
	} else {
		delete(requestCopy.Header, HeaderAuthorization)
	}
	err := deleteNonSignedHeaders(requestCopy, authorization)
	if err != nil {
		return false, err
	}
	var signatures string
	signatures, err = s.getAuthValueStr(requestCopy)
	if err != nil {
		return false, err
	}
	return signatures == authorization, nil
}

func deleteNonSignedHeaders(request *http.Request, authorization string) error {
	startIndex := strings.Index(authorization, SignedHeadersPrefix)
	if startIndex == -1 {
		return errors.New("the authorization format is incorrect, signedHeaders not found")
	}

	// Extract the request header used for signing
	startIndex += len(SignedHeadersPrefix)
	endIndex := strings.Index(authorization[startIndex:], ",")
	if endIndex == -1 {
		endIndex = len(authorization) - startIndex
	}
	signedHeaders := authorization[startIndex : startIndex+endIndex]
	headers := strings.Split(signedHeaders, ";")
	signedHeadersMap := make(map[string]bool)
	for _, header := range headers {
		signedHeadersMap[strings.ToLower(header)] = true
	}

	// Delete headers that are not in the signature header list
	for key := range request.Header {
		if !signedHeadersMap[strings.ToLower(key)] {
			request.Header.Del(key)
		}
	}
	return nil
}
