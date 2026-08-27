/*
 *  Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
 */

package core

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"
)

const (
	derivationKeyLength       = 32
	apic                      = "apic"
	credentialScopeDateFormat = "20060102"
)

type signV11 struct {
	signer          *Signer
	credentialScope string
}

func (s *signV11) stringToSign(canonicalRequest string, t time.Time) (string, error) {
	signer := s.signer
	hashStruct := signer.HashFunc()
	_, err := hashStruct.Write([]byte(canonicalRequest))
	if err != nil {
		return "", err
	}
	s.setCredentialScope(t)
	return fmt.Sprintf("%s\n%s\n%s\n%x", signer.Algorithm, t.UTC().Format(BasicDateFormat),
		s.credentialScope, hashStruct.Sum(nil)), nil
}

func (s *signV11) authHeaderValue(signatureStr, accessKeyStr string, signedHeaders []string) string {
	return fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s", s.signer.Algorithm,
		accessKeyStr, s.credentialScope, strings.Join(signedHeaders, ";"), signatureStr)
}

func (s *signV11) getRealUseSecret(key, secret string) (string, error) {
	tempByteArr, err := s.hkdf(key, secret, s.credentialScope, derivationKeyLength)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(tempByteArr), nil
}

func (s *signV11) setCredentialScope(t time.Time) string {
	dateStr := t.Format(credentialScopeDateFormat)
	s.credentialScope = dateStr + "/" + s.signer.RegionId + "/" + apic
	return s.credentialScope
}

func (s *signV11) hkdf(key, secret, credentialScope string, resLength int) ([]byte, error) {
	salt := []byte(key)
	ikm := []byte(secret)
	info := []byte(credentialScope)
	r := hkdf.New(s.signer.HashFunc, ikm, salt, info)
	okm := make([]byte, resLength)
	if _, err := io.ReadFull(r, okm); err != nil {
		return nil, err
	}
	return okm, nil
}

func (s *signV11) generateAuth(canonicalRequest string, t time.Time, signedHeaders []string) (string, error) {
	signer := s.signer
	if signer == nil {
		return EmptyString, errors.New("the signer is nil")
	}
	stringToSignStr, err := s.stringToSign(canonicalRequest, t)
	if err != nil {
		return EmptyString, err
	}
	realUseSecret, err := s.getRealUseSecret(signer.Key, signer.Secret)
	if err != nil {
		return EmptyString, err
	}
	signatureStr, err := signer.SignStringToSign(stringToSignStr, []byte(realUseSecret))
	if err != nil {
		return EmptyString, err
	}

	return s.authHeaderValue(signatureStr, signer.Key, signedHeaders), nil
}
