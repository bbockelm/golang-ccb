//go:build !unix

package main

func descriptorLimit() uint64 { return 0 }
