//
// Copyright 2018 Moriyoshi Koizumi
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
package gonetsnmp

import (
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	InitMIB()
	defer ShutdownMIB()
	os.Exit(m.Run())
}

func TestStringToOID(t *testing.T) {
	oid, err := StringToOid("1.3.6.1.4.1.4")
	if assert.NoError(t, err) {
		assert.Equal(t, OID{1, 3, 6, 1, 4, 1, 4}, oid)
	}
}

func TestOIDToString(t *testing.T) {
	assert.Equal(t, []byte("1.3.6.1.4.1.4"), OidToString(OID{1, 3, 6, 1, 4, 1, 4}))
}

func TestGetAbbreviatedName(t *testing.T) {
	oid, err := StringToOid("1.3.6.1.4.1")
	if assert.NoError(t, err) {
		assert.Equal(t, "SNMPv2-SMI::enterprises", GetAbbreviatedName(oid))
	}
}
