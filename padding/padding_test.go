package padding

import (
	"bytes"
	"testing"
)

func TestPaddingRoundTrip(t *testing.T) {
	data := []byte("abcde")
	padded := AddPadding(data)
	unpadded, err := RemovePadding(padded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(unpadded, data) {
		t.Fatalf("got %q, want %q", unpadded, data)
	}
}
