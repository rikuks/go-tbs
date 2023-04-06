//go:build windows

package tbs

import (
	"fmt"
	"testing"
)

func TestSubmitCommand(t *testing.T) {
	context, err := CreateContext(2, IncludeTpm20)
	if err != nil {
		t.Fatal(err)
	}
	defer CloseContext(context)
	out := make([]byte, 2048)
	n, err := SubmitCommand(context, PriorityNormal, []byte{128, 1, 0, 0, 0, 12, 0, 0, 1, 123, 0, 32}, out)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("Result:", out[:n])
}

func TestSubmitCommandDirect(t *testing.T) {
	context, err := CreateContext(2, IncludeTpm20)
	if err != nil {
		t.Fatal(err)
	}
	defer CloseContext(context)
	out := make([]byte, 2048)
	n, err := SubmitCommandDirect(context, []byte{128, 1, 0, 0, 0, 12, 0, 0, 1, 123, 0, 32}, out)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("Result:", out[:n])
}
