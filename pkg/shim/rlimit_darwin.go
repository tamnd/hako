package shim

// RLIMIT_NPROC from <sys/resource.h>; x/sys/unix does not export it for
// darwin.
const rlimitNproc = 7
