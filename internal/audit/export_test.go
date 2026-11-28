package audit

import "os"

// Seams for the tests of other packages that live in package audit_test.

func (l *Log) SetSyncDirFn(f func(string) error)   { l.syncDirFn = f }
func (l *Log) SetCloseFile(f func(*os.File) error) { l.closeFile = f }
