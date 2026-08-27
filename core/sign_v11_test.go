/*
 *  Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
 */

package core

import (
	"crypto/sha256"
	"errors"
	"reflect"
	"time"

	"github.com/agiledragon/gomonkey/v2"
)

var _ = Describe("signV11", func() {
	var (
		signer    *Signer
		v11Signer *signV11
		testTime  time.Time
		patch     *gomonkey.Patches
	)

	BeforeEach(func() {
		signer = &Signer{
			Key:       "test-key",
			Secret:    "test-secret",
			Algorithm: "V11-HMAC-SHA256",
			RegionId:  "test-region",
			HashFunc:  sha256.New,
		}
		v11Signer = &signV11{
			signer: signer,
		}
		testTime = time.Date(2023, time.January, 1, 0, 0, 0, 0, time.UTC)
		patch = gomonkey.NewPatches()
	})

	AfterEach(func() {
		patch.Reset()
	})

	Describe("stringToSign", func() {
		It("should generate correct string to sign", func() {
			canonicalRequest := "test canonical request"
			stringToSign, err := v11Signer.stringToSign(canonicalRequest, testTime)
			Expect(err).NotTo(HaveOccurred())
			Expect(stringToSign).To(ContainSubstring("V11-HMAC-SHA256"))
			Expect(stringToSign).To(ContainSubstring("20230101T000000Z"))
			Expect(stringToSign).To(ContainSubstring("20230101/test-region/apic"))
		})
	})

	Describe("authHeaderValue", func() {
		It("should generate correct auth header", func() {
			signature := "test-signature"
			accessKey := "test-access-key"
			signedHeaders := []string{"host", "content-type"}
			v11Signer.credentialScope = "20230101/test-region/apic"
			authHeader := v11Signer.authHeaderValue(signature, accessKey, signedHeaders)
			Expect(authHeader).To(ContainSubstring("V11-HMAC-SHA256"))
			Expect(authHeader).To(ContainSubstring("Credential=test-access-key/20230101/test-region/apic"))
			Expect(authHeader).To(ContainSubstring("SignedHeaders=host;content-type"))
			Expect(authHeader).To(ContainSubstring("Signature=test-signature"))
		})
	})

	Describe("getRealUseSecret", func() {
		It("should generate correct derived secret", func() {
			v11Signer.setCredentialScope(time.Now())
			derivedSecret, err := v11Signer.getRealUseSecret("test-key", "test-secret")
			Expect(err).NotTo(HaveOccurred())
			Expect(derivedSecret).To(HaveLen(64)) // hex encoded 32 bytes
		})
	})

	Describe("setCredentialScope", func() {
		It("should generate correct credential scope", func() {
			scope := v11Signer.setCredentialScope(testTime)
			Expect(scope).To(Equal("20230101/test-region/apic"))
		})
	})

	Describe("hkdf", func() {
		It("should generate correct derived key", func() {
			key, err := v11Signer.hkdf("test-key", "test-secret", "test-scope", derivationKeyLength)
			Expect(err).NotTo(HaveOccurred())
			Expect(key).To(HaveLen(derivationKeyLength))
		})
	})

	Describe("generateAuth", func() {
		It("should generate complete auth header", func() {
			canonicalRequest := "test canonical request"
			signedHeaders := []string{"host", "content-type"}

			authHeader, err := v11Signer.generateAuth(canonicalRequest, testTime, signedHeaders)
			Expect(err).NotTo(HaveOccurred())
			Expect(authHeader).To(ContainSubstring("V11-HMAC-SHA256"))
			Expect(authHeader).To(ContainSubstring("Credential=test-key/20230101/test-region/apic"))
			Expect(authHeader).To(ContainSubstring("SignedHeaders=host;content-type"))
			Expect(authHeader).To(ContainSubstring("Signature="))
		})

		It("generate auth header failed, stringToSign return error", func() {
			expErr := errors.New("hash write fail")
			patch.ApplyPrivateMethod(reflect.TypeOf(&signV11{}), "stringToSign",
				func(_ *signV11, canonicalRequest string, t time.Time) (string, error) {
					return "", expErr
				})
			authHeader, err := v11Signer.generateAuth("", testTime, []string{})
			Expect(err).To(Equal(expErr))
			Expect(authHeader).To(Equal(""))
		})

		It("generate auth header failed, getRealUseSecret return error", func() {
			expErr := errors.New("hkdf fail")
			patch.ApplyPrivateMethod(reflect.TypeOf(&signV11{}), "getRealUseSecret",
				func(_ *signV11, key, secret string) (string, error) {
					return "", expErr
				})
			canonicalRequest := "test canonical request"
			signedHeaders := []string{"host", "content-type"}
			authHeader, err := v11Signer.generateAuth(canonicalRequest, testTime, signedHeaders)
			Expect(err).To(Equal(expErr))
			Expect(authHeader).To(Equal(""))
		})

		It("generate auth header failed, SignStringToSign return error", func() {
			expErr := errors.New("hm write fail")
			patch.ApplyMethod(reflect.TypeOf(&Signer{}), "SignStringToSign",
				func(_ *Signer, stringToSign string, signingKey []byte) (string, error) {
					return "", expErr
				})
			canonicalRequest := "test canonical request"
			signedHeaders := []string{"host", "content-type"}
			authHeader, err := v11Signer.generateAuth(canonicalRequest, testTime, signedHeaders)
			Expect(err).To(Equal(expErr))
			Expect(authHeader).To(Equal(""))
		})

		It("generate auth header failed, signer is nil", func() {
			expErr := errors.New("the signer is nil")
			canonicalRequest := "test canonical request"
			signedHeaders := []string{"host", "content-type"}
			v11Signer.signer = nil
			authHeader, err := v11Signer.generateAuth(canonicalRequest, testTime, signedHeaders)
			Expect(err).To(Equal(expErr))
			Expect(authHeader).To(Equal(""))
		})
	})
})
