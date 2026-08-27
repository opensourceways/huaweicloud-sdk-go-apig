/*
 *  Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
 */

package core

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestCore(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	ginkgo.RunSpecs(t, "Core Suite")
}

var (
	Describe         = ginkgo.Describe
	BeforeEach       = ginkgo.BeforeEach
	It               = ginkgo.It
	Context          = ginkgo.Context
	AfterEach        = ginkgo.AfterEach
	Expect           = gomega.Expect
	HaveOccurred     = gomega.HaveOccurred
	ContainSubstring = gomega.ContainSubstring
	HaveLen          = gomega.HaveLen
	Equal            = gomega.Equal
	BeEmpty          = gomega.BeEmpty
	BeTrue           = gomega.BeTrue
	BeFalse          = gomega.BeFalse
	HaveKeyWithValue = gomega.HaveKeyWithValue
	HaveKey          = gomega.HaveKey
)
