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

// #cgo LDFLAGS: -lsnmp
// #include <stdlib.h>
// #include <net-snmp/net-snmp-config.h>
// #include <net-snmp/mib_api.h>
import "C"

import (
	"fmt"
	"strconv"
	"strings"
)

type OID []int

func OidToString(oid OID) []byte {
	var buf []byte
	for i, v := range oid {
		if i > 0 {
			buf = append(buf, '.')
		}
		buf = strconv.AppendInt(buf, int64(v), 10)
	}
	return buf
}

func StringToOid(oidStr string) (OID, error) {
	s := strings.Split(oidStr, ".")
	var buf OID
	for i, sv := range s {
		if len(sv) == 0 {
			if i == 0 {
				continue
			} else {
				return nil, fmt.Errorf("empty component found in OID")
			}
		}
		v, err := strconv.Atoi(sv)
		if err != nil {
			return nil, err
		}
		buf = append(buf, v)
	}
	return buf, nil
}

func walk(oid OID, t *C.struct_tree) (retval []*C.struct_tree) {
	for _, v := range oid {
		for ; t != nil; t = t.next_peer {
			if C.oid(t.subid) == C.oid(v) {
				retval = append(retval, t)
				t = t.child_list
				break
			}
		}
		if t == nil {
			break
		}
	}
	return
}

func InitMIB() {
	C.init_mib()
}

func ShutdownMIB() {
	C.shutdown_mib()
}

func ReadAllMIBs() {
	C.read_all_mibs()
}

type MIBNode struct {
	ID     int
	Label  string
	Module string
}

func GetMIBNodes(oid OID) (retval []MIBNode) {
	ts := walk(oid, C.get_tree_head())
	for _, t := range ts {
		modName := ""
		m := C.find_module(t.modid)
		if m != nil {
			modName = C.GoString(m.name)
		}
		retval = append(retval, MIBNode{
			ID:     int(t.subid),
			Label:  C.GoString(t.label),
			Module: modName,
		})
	}
	return
}

func AppendAbbreviatedName(buf []byte, oid OID) []byte {
	nodes := GetMIBNodes(oid)
	l := len(nodes)
	if l > 0 {
		n := nodes[l-1]
		if n.Module != "" {
			buf = append(buf, []byte(n.Module)...)
			buf = append(buf, ':', ':')
		}
		buf = append(buf, []byte(n.Label)...)
	}
	for i, v := range oid[l:] {
		if i+l > 0 {
			buf = append(buf, '.')
		}
		buf = strconv.AppendInt(buf, int64(v), 10)
	}
	return buf
}

func GetAbbreviatedName(oid OID) string {
	var buf []byte
	buf = AppendAbbreviatedName(buf, oid)
	return string(buf)
}
