package main

import (
	"fmt"
	"github.com/jessevdk/go-flags"
	"golang.org/x/crypto/sha3"
	"gopkg.in/kothar/brotli-go.v0/dec"
	"gopkg.in/kothar/brotli-go.v0/enc"
	"hash"
	"io"
	"os"
	"bytes"
)

type Options struct {
	Verbose          bool `short:"v" long:"verbose" description:"Show verbose debug information"`
	DecompressFlag   bool `short:"d" long:"decompress" description:"Decompress the input file"`
	CompressionLevel int  `long:"level" description:"Compression level, 0 - 11" default:"5"`
	Version          bool `long:"version" description:"Show version information"`
	StandardOutput   bool `short:"c" long:"stdout" description:"Output to standard out"`
}

func versionInformation() {
	fmt.Printf("IZip v0.6\n")
	fmt.Printf("Copyright (C) 2015-2016 Ian S. Nelson <nelsonis@pobox.com>\n")
	os.Exit(0)
}

func init() {
}

func main() {
	var options Options
	var parser = flags.NewParser(&options, flags.Default)
	inputFileName, err := parser.Parse()
	checkError(err)

	if options.Version {
		versionInformation()
	}

	if options.CompressionLevel < 0 {
		options.CompressionLevel = 0
	}
	if options.CompressionLevel > 11 {
		options.CompressionLevel = 11
	}

	for _, fileName := range inputFileName {
		if options.DecompressFlag {
			decompressFile(fileName, decompressFileName(fileName), options.Verbose, options.StandardOutput)
		} else {
			compressFile(fileName, compressFileName(fileName), options.CompressionLevel, options.Verbose, options.StandardOutput)
		}
	}
}

func decompressFileName(inFileName string) string {
	if inFileName == "-"  {
		return inFileName
	}
		
	return inFileName[0 : len(inFileName)-3]
}

func compressFileName(inFileName string) string {
	if inFileName == "-"  {
		return inFileName
	}
	return inFileName + ".iz"
}

func checkError(err error) {
	if err != nil {
		os.Exit(1)
	}
}

func compressFile(inFileName string, outFileName string, level int, verbose bool, standardOutput bool) {
	var inFile *os.File
	var err error
	if inFileName == "-" {
		fmt.Printf("Using stdin!\n")
		inFile = os.Stdin
	} else {
		inFile, err = os.Open(inFileName)
		checkError(err)
	}
	defer inFile.Close()
	var outFile *os.File
	
	if !standardOutput {
		outFile, err = os.Create(outFileName)
		checkError(err)
	} else {
		outFile = os.Stdout
	}

	defer outFile.Close()

	hasher := NewHashWriter()
	archiveWriter := NewArchiveWriter(hasher,outFile) 
	teeReader := io.TeeReader(inFile, hasher)

	params := enc.NewBrotliParams()
	params.SetQuality(level)
	params.SetLgwin(24)
	brotliWriter := enc.NewBrotliWriter(params, archiveWriter)
	defer brotliWriter.Close()
	
	// Perform the actual compression
	io.Copy(brotliWriter, teeReader)		
}

// Flag IZ0x01   3 bytes
// Compressed data
// 32 bytes of hash
func writeHeader(outFile io.Writer) {
	var header [3]byte
	header[0] = 'I'
	header[1] = 'Z'
	header[2] = 0x1
	outFile.Write(header[:])
}

func readHeader(inFile io.Reader) bool {
	var header [3]byte
	inFile.Read(header[:])
	if header[0] == 'I' &&
	   header[1] == 'Z' &&
	   header[2] == 0x1 {
		return true
	}
	return false
}

func decompressFile(inFileName string, outFileName string, verbose bool, standardOutput bool) {
	var inFile *os.File
	var err error
	if inFileName != "-" {
		inFile, err = os.Open(inFileName)
		checkError(err)
	} else {
		inFile = os.Stdin
	}
	
	hashtail := NewHashCatcher()
	hashWriter := NewHashWriter()
			
	if(!readHeader(inFile)) {
	    fmt.Printf("Invalid header!\n");
	    os.Exit(1)
	}
	
	readerTee := io.TeeReader(inFile, hashtail)
	
	brotliReader := dec.NewBrotliReader(readerTee)
	defer brotliReader.Close()

	var outFile *os.File
	if !standardOutput {
		outFile, err = os.Create(outFileName)
		checkError(err)
	} else {
		outFile = os.Stdout
	}

	outFileMulti := io.MultiWriter(outFile, hashWriter)

	io.Copy(outFileMulti, brotliReader)
	outFile.Close()

	hashOutput := hashWriter.Sum()

	if bytes.Compare(hashOutput, hashtail.hashbuffer[:]) == 0 {
		os.Exit(0)
    } else {
        os.Exit(1)
    }
}


/** Writer that performs hashing */
type HashWriter struct {
	hash hash.Hash
}

func NewHashWriter() *HashWriter {
	return &HashWriter {
		hash: sha3.New256(),
	}
}

func (h* HashWriter)Write(buffer []byte)(int, error) {
	return h.hash.Write(buffer)
}

func (h* HashWriter)Close() error {
	return nil;
}

func (h* HashWriter)Sum() []byte {
	return h.hash.Sum(nil);
}


type HashCatcher struct {
	hashbuffer [32]byte
}

func NewHashCatcher() *HashCatcher {
	var tmpBuffer [32]byte
	return &HashCatcher {
		hashbuffer:tmpBuffer,
	}
}

func (h* HashCatcher)Write(buffer []byte)(int, error) {
	if(len(buffer) > 32) {
		copy(h.hashbuffer[:],buffer[len(buffer)-32:len(buffer)]) 
	} else {
		myLen := len(buffer)
		var copyBuffer [32]byte
		copy(copyBuffer[:],h.hashbuffer[:])
		copy(h.hashbuffer[:], copyBuffer[32-myLen:])
		copy(h.hashbuffer[32-myLen:], buffer)
	}
	return len(buffer),nil
}

func (h* HashCatcher)Close() error {
	return nil;
}



/**
  Encapsulate the archive format.   Header, compressed data, sha3-256 of the input data
*/
type ArchiveWriter struct {
	writer io.WriteCloser
	hashWriter *HashWriter
}

func NewArchiveWriter(hashWriter *HashWriter, output io.WriteCloser) *ArchiveWriter {
	writeHeader(output)
	return &ArchiveWriter {
		writer: output,
		hashWriter: hashWriter,
	}
}

func (w* ArchiveWriter)Write(buffer []byte)(int,error) {
	return w.writer.Write(buffer)
}

func (w* ArchiveWriter)Close() error {
	hashOutput := w.hashWriter.Sum()
	_,err:=w.writer.Write(hashOutput)
	checkError(err)
	w.writer.Close()
	return w.writer.Close()
}


