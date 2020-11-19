package io

import "os"

func Open_file(fname string) []byte {

	f, err := os.Open(fname)
	if err != nil {
		print(err)
		os.Exit(1)
	}

	l, _ := f.Seek(0, 2)
	f.Seek(0, 0)
	buff := make([]byte, l)
	f.Read(buff)

	if err != nil {
		print(err)
		os.Exit(1)
	}

	return buff
}
