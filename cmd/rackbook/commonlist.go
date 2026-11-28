package main

import "github.com/kazuhahub/rackbook/internal/accounts"

// testCommonList is the list of common passwords the server and the account commands use instead of the embedded one. It is nil, always,
// in production, which has no flag and no file for it: the list is the one embedded in the build. Tests set it to run local sign-in with a
// list of the size the gate asks for (accounts.MinCommonPasswords).
var testCommonList *accounts.CommonList
