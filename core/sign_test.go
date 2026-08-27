/*
 *  Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
 */

package core

import (
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"

	"github.com/agiledragon/gomonkey/v2"
)

var _ = Describe("Signer", func() {
	var (
		signer  *Signer
		request *http.Request
		patch   *gomonkey.Patches
	)

	BeforeEach(func() {
		signer = &Signer{
			Key:       "test-key",
			Secret:    "test-secret",
			Algorithm: DefaultAlgorithm,
		}
		var errHttp error
		request, errHttp = http.NewRequest("GET", "http://example.com", nil)
		Expect(errHttp).NotTo(HaveOccurred())
		patch = gomonkey.NewPatches()
	})

	AfterEach(func() {
		patch.Reset()
	})

	Describe("setSigner", func() {
		It("should set default algorithm when empty", func() {
			signer.Algorithm = ""
			err := signer.setSigner()
			Expect(err).NotTo(HaveOccurred())
			Expect(signer.Algorithm).To(Equal(DefaultAlgorithm))
		})

		It("should error with unsupported algorithm", func() {
			signer.Algorithm = "invalid-algorithm"
			err := signer.setSigner()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("unsupported algorithm"))
		})

		It("should error with V11 algorithm and empty region", func() {
			signer.Algorithm = "V11-HMAC-SHA256"
			signer.RegionId = ""
			err := signer.setSigner()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("regionId cannot be empty"))
		})
	})

	Describe("SignStringToSign", func() {
		It("should generate correct signature", func() {
			err := signer.setSigner()
			Expect(err).NotTo(HaveOccurred())

			stringToSign := "test-string"
			signature, err := signer.SignStringToSign(stringToSign, []byte(signer.Secret))
			Expect(err).NotTo(HaveOccurred())
			Expect(signature).NotTo(BeEmpty())
		})
	})

	Describe("authHeaderValue", func() {
		It("should generate correct auth header", func() {
			signature := "test-signature"
			accessKey := "test-access-key"
			signedHeaders := []string{"host", "content-type"}

			authHeader := signer.AuthHeaderValue(signature, accessKey, signedHeaders)
			Expect(authHeader).To(ContainSubstring("SDK-HMAC-SHA256"))
			Expect(authHeader).To(ContainSubstring("Access=test-access-key"))
			Expect(authHeader).To(ContainSubstring("SignedHeaders=host;content-type"))
			Expect(authHeader).To(ContainSubstring("Signature=test-signature"))
		})
	})

	Context("when authorization header contains signed headers", func() {
		It("should keep only signed headers", func() {
			request.Header.Set("Header1", "value1")
			request.Header.Set("Header2", "value2")
			request.Header.Set("Header3", "value3")
			authorization := "V11-HMAC-SHA256 Credential=AKID/20150830/us-east-1/service/aws4_request, SignedHeaders=header1;header3, Signature=fe5f80f7"

			err := deleteNonSignedHeaders(request, authorization)

			Expect(err).NotTo(HaveOccurred())
			Expect(request.Header).To(HaveKeyWithValue("Header1", []string{"value1"}))
			Expect(request.Header).To(HaveKeyWithValue("Header3", []string{"value3"}))
			Expect(request.Header).NotTo(HaveKey("Header2"))
		})

		It("should return error when SignedHeaders not found", func() {
			request.Header.Set("Header1", "value1")
			request.Header.Set("Header2", "value2")
			authorization := "SDK-HMAC-SHA256 Access=AKID, Signature=fe5f80f7"

			err := deleteNonSignedHeaders(request, authorization)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("signedHeaders not found"))
		})

		It("should keep all signed headers", func() {
			request.Header.Set("Header1", "value1")
			request.Header.Set("Header2", "value2")
			request.Header.Set("Header3", "value3")

			authorization := "SDK-HMAC-SHA256 Access=AKID,, SignedHeaders=header1;header2;header3, Signature=fe5f80f7"

			err := deleteNonSignedHeaders(request, authorization)
			Expect(err).NotTo(HaveOccurred())
			Expect(request.Header).To(HaveKeyWithValue("Header1", []string{"value1"}))
			Expect(request.Header).To(HaveKeyWithValue("Header2", []string{"value2"}))
			Expect(request.Header).To(HaveKeyWithValue("Header3", []string{"value3"}))
		})

		It("should match headers case-insensitively", func() {
			request.Header.Set("HEADER1", "value1")
			request.Header.Set("header2", "value2")

			authorization := "SDK-HMAC-SHA256 Access=AKID, SignedHeaders=header1, Signature=fe5f80f7"

			err := deleteNonSignedHeaders(request, authorization)
			Expect(err).NotTo(HaveOccurred())
			Expect(request.Header).To(HaveKeyWithValue("Header1", []string{"value1"}))
			Expect(request.Header).NotTo(HaveKey("header2"))
		})
	})
})

var _ = Describe("Signature Functions", func() {
	Describe("CanonicalRequest", func() {
		It("should build correct canonical request", func() {
			req := httptest.NewRequest("GET", "http://example.com/path?param=value", nil)
			req.Header.Set("Host", "example.com")
			req.Header.Set("Content-Type", "application/json")

			hashFunc := sha256.New()
			canonicalReq, err := CanonicalRequest(req, []string{"host", "content-type"}, hashFunc)
			Expect(err).NotTo(HaveOccurred())
			Expect(canonicalReq).To(ContainSubstring("GET"))
			Expect(canonicalReq).To(ContainSubstring("/path/"))
			Expect(canonicalReq).To(ContainSubstring("host:example.com"))
			Expect(canonicalReq).To(ContainSubstring("content-type:application/json"))
		})
	})

	Describe("CanonicalURI", func() {
		It("should escape and normalize URI", func() {
			req := httptest.NewRequest("GET", "http://example.com/path/_:test", nil)
			uri := CanonicalURI(req)
			Expect(uri).To(Equal("/path/_%3Atest/"))
		})
	})

	Describe("CanonicalQueryString", func() {
		It("should sort and escape query parameters", func() {
			req := httptest.NewRequest("GET", "http://example.com/path?b=2&a=1&b=3", nil)
			query := CanonicalQueryString(req)
			Expect(query).To(Equal("a=1&b=2&b=3"))
		})
	})

	Describe("CanonicalHeaders", func() {
		It("should format headers correctly", func() {
			req := httptest.NewRequest("GET", "http://example.com", nil)
			req.Header.Set("Host", "example.com")
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Custom", "value")

			headers := CanonicalHeaders(req, []string{"host", "content-type"})
			Expect(headers).To(ContainSubstring("host:example.com\n"))
			Expect(headers).To(ContainSubstring("content-type:application/json\n"))
		})
	})

	Describe("RequestPayload", func() {
		It("should read request body", func() {
			body := `{"test":"data"}`
			req := httptest.NewRequest("POST", "http://example.com", strings.NewReader(body))

			payload, err := RequestPayload(req)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(payload)).To(Equal(body))
		})
	})

	Describe("HexEncodeSHA256Hash", func() {
		It("should generate correct hash", func() {
			hashFunc := sha256.New()
			hash, err := HexEncodeSHA256Hash([]byte("test data"), hashFunc)
			Expect(err).NotTo(HaveOccurred())
			Expect(hash).To(HaveLen(64)) // SHA256 hex is 64 chars
		})
	})
})

var _ = Describe("Request Signing", func() {
	var (
		patch *gomonkey.Patches
	)

	BeforeEach(func() {
		patch = gomonkey.NewPatches()
	})

	AfterEach(func() {
		patch.Reset()
	})
	Describe("SignRequest", func() {
		var (
			req *http.Request
			err error
		)

		BeforeEach(func() {
			req = httptest.NewRequest("POST", "http://example.com/api", strings.NewReader(`{"test":"data"}`))
			req.Header.Set("Host", "example.com")
			req.Header.Set("Content-Type", "application/json")
		})

		It("should sign request with default algorithm", func() {
			signer := &Signer{
				Key:    "test-key",
				Secret: "test-secret",
			}

			err = signer.Sign(req)
			Expect(err).NotTo(HaveOccurred())
			Expect(req.Header.Get(HeaderAuthorization)).NotTo(BeEmpty())
		})

		It("should sign request with V11 algorithm", func() {
			signer := &Signer{
				Key:       "test-key",
				Secret:    "test-secret",
				Algorithm: "V11-HMAC-SHA256",
				RegionId:  "test-region",
			}

			err = signer.Sign(req)
			Expect(err).NotTo(HaveOccurred())
			Expect(req.Header.Get(HeaderAuthorization)).NotTo(BeEmpty())
		})

		It("sign request failed, setSigner failed", func() {
			signer := &Signer{
				Key:       "test-key",
				Secret:    "test-secret",
				Algorithm: "V11-HMAC-SHA256",
				RegionId:  "test-region",
			}
			expErr := errors.New("setSigner fail")
			patch.ApplyPrivateMethod(reflect.TypeOf(&Signer{}), "setSigner",
				func(_ *Signer) error {
					return expErr
				})
			err = signer.Sign(req)
			Expect(err).To(Equal(expErr))
		})

		It("sign request failed, getAuthValueStr failed", func() {
			signer := &Signer{
				Key:       "test-key",
				Secret:    "test-secret",
				Algorithm: "V11-HMAC-SHA256",
				RegionId:  "test-region",
			}
			expErr := errors.New("getAuthValueStr fail")
			mockGetAuthValueStr(patch, expErr)
			err = signer.Sign(req)
			Expect(err).To(Equal(expErr))
		})
	})

	Describe("Verify", func() {
		var (
			req *http.Request
			err error
		)

		BeforeEach(func() {
			req = httptest.NewRequest("POST", "http://example.com/api", strings.NewReader(`{"test":"data"}`))
			req.Header.Set("Host", "example.com")
			req.Header.Set("Content-Type", "application/json")
		})

		It("should verify valid signature", func() {
			signer := &Signer{
				Key:       "test-key",
				Secret:    "test-secret",
				Algorithm: DefaultAlgorithm,
			}
			err = signer.Sign(req)
			Expect(err).NotTo(HaveOccurred())

			authorization := req.Header.Get(HeaderAuthorization)
			isValid, err := signer.Verify(req, authorization)
			Expect(err).NotTo(HaveOccurred())
			Expect(isValid).To(BeTrue())
		})

		It("should reject invalid signature", func() {
			signer := &Signer{
				Key:       "test-key",
				Secret:    "test-secret",
				Algorithm: DefaultAlgorithm,
			}
			err = signer.Sign(req)
			Expect(err).NotTo(HaveOccurred())

			req.Header.Set("Content-Type", "invalid-type")
			authorization := req.Header.Get(HeaderAuthorization)
			isValid, err := signer.Verify(req, authorization)
			Expect(err).NotTo(HaveOccurred())
			Expect(isValid).To(BeFalse())
		})

		It("should verify valid signature, use CustomAuthHeader", func() {
			signer := &Signer{
				Key:              "test-key",
				Secret:           "test-secret",
				Algorithm:        DefaultAlgorithm,
				CustomAuthHeader: "Auth",
			}

			err = signer.Sign(req)
			Expect(err).NotTo(HaveOccurred())

			authorization := req.Header.Get(signer.CustomAuthHeader)
			isValid, err := signer.Verify(req, authorization)
			Expect(err).NotTo(HaveOccurred())
			Expect(isValid).To(BeTrue())
		})

		It("verify signature failed, deleteNonSignedHeaders return error", func() {
			signer := &Signer{
				Key:       "test-key",
				Secret:    "test-secret",
				Algorithm: DefaultAlgorithm,
			}
			err = signer.Sign(req)
			Expect(err).NotTo(HaveOccurred())
			expErr := errors.New("deleteNonSignedHeaders fail")
			patch.ApplyFunc(deleteNonSignedHeaders, func(request *http.Request, authorization string) error {
				return expErr
			})
			authorization := req.Header.Get(HeaderAuthorization)
			isValid, err := signer.Verify(req, authorization)
			Expect(err).To(Equal(expErr))
			Expect(isValid).To(BeFalse())
		})

		It("verify signature failed, getAuthValueStr return error", func() {
			signer := &Signer{
				Key:       "test-key",
				Secret:    "test-secret",
				Algorithm: DefaultAlgorithm,
			}
			err = signer.Sign(req)
			Expect(err).NotTo(HaveOccurred())
			expErr := errors.New("getAuthValueStr fail")
			mockGetAuthValueStr(patch, expErr)
			authorization := req.Header.Get(HeaderAuthorization)
			isValid, err := signer.Verify(req, authorization)
			Expect(err).To(Equal(expErr))
			Expect(isValid).To(BeFalse())
		})
	})
})

func mockGetAuthValueStr(patch *gomonkey.Patches, expErr error) *gomonkey.Patches {
	return patch.ApplyPrivateMethod(reflect.TypeOf(&Signer{}), "getAuthValueStr",
		func(_ *Signer, request *http.Request) (string, error) {
			return "", expErr
		})
}
