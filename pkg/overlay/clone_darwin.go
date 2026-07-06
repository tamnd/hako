package overlay

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// cloneTree makes dst a copy-on-write clone of src using APFS clonefile.
// clonefile on a directory clones the whole hierarchy, sharing blocks
// until something is written, so a large project clones in milliseconds
// and costs no extra disk until the command edits a file. dst must not
// already exist.
func cloneTree(src, dst string) error {
	if err := unix.Clonefile(src, dst, 0); err != nil {
		return fmt.Errorf("overlay: clonefile %s: %w", src, err)
	}
	return nil
}
