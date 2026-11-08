package rw

import (
	"io"

	"github.com/metacubex/sing/common"
	"github.com/metacubex/sing/common/binary"
)

type stubByteReader struct {
	io.Reader
}

func (r stubByteReader) ReadByte() (byte, error) {
	var b [1]byte
	var n int
	var err error
	for n == 0 && err == nil {
		n, err = r.Read(b[:])
	}

	if n == 1 && err == io.EOF {
		err = nil
	}
	return b[0], err
}

func ToByteReader(reader io.Reader) io.ByteReader {
	if byteReader, ok := reader.(io.ByteReader); ok {
		return byteReader
	}
	return &stubByteReader{reader}
}

func ReadUVariant(reader io.Reader) (uint64, error) {
	return binary.ReadUvarint(ToByteReader(reader))
}

func UvarintLen(x uint64) int {
	switch {
	case x < 1<<(7*1):
		return 1
	case x < 1<<(7*2):
		return 2
	case x < 1<<(7*3):
		return 3
	case x < 1<<(7*4):
		return 4
	case x < 1<<(7*5):
		return 5
	case x < 1<<(7*6):
		return 6
	case x < 1<<(7*7):
		return 7
	default:
		return 8
	}
}

func WriteUVariant(writer io.Writer, value uint64) error {
	var b [8]byte
	return common.Error(writer.Write(b[:binary.PutUvarint(b[:], value)]))
}

func WriteVString(writer io.Writer, value string) error {
	err := WriteUVariant(writer, uint64(len(value)))
	if err != nil {
		return err
	}
	return WriteString(writer, value)
}

func ReadVString(reader io.Reader) (string, error) {
	length, err := ReadUVariant(reader)
	if err != nil {
		return "", err
	}
	return ReadString(reader, int(length))
}
