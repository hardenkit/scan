package aistack

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

// pickleImports lists every module.name a pickle stream imports (GLOBAL,
// INST and STACK_GLOBAL opcodes) without running it. Loading a pickle calls
// those imports, which is how a model file runs code. An import whose name
// can't be worked out statically is reported as "?".
//
// Several pickles may be concatenated (PyTorch's legacy format); parsing
// continues while the next byte starts a new protocol-2+ pickle.
func pickleImports(r io.Reader) ([]string, error) {
	br := bufio.NewReaderSize(r, 64<<10)
	var imports []string
	for {
		got, err := pickleOnce(br)
		imports = append(imports, got...)
		if err != nil {
			return imports, err
		}
		next, err := br.Peek(1)
		if err != nil || next[0] != 0x80 {
			return imports, nil
		}
	}
}

var errPickle = errors.New("not a valid pickle stream")

func pickleOnce(br *bufio.Reader) ([]string, error) {
	var (
		imports []string
		strs    []string // strings pushed since the last non-string op
		memo    = map[uint64]string{}
		memoLen uint64
		last    string // last value pushed, if it was a string
		isStr   bool
	)
	pushStr := func(s string) { strs = append(strs, s); last, isStr = s, true }
	other := func() { strs = strs[:0]; isStr = false }
	memoize := func(idx uint64) {
		if isStr {
			memo[idx] = last
		}
	}
	get := func(idx uint64) {
		if s, ok := memo[idx]; ok {
			pushStr(s)
		} else {
			other()
		}
	}

	for {
		op, err := br.ReadByte()
		if err != nil {
			return imports, fmt.Errorf("%w: unexpected end", errPickle)
		}
		switch op {
		case '.': // STOP
			return imports, nil

		// Imports.
		case 'c', 'i': // GLOBAL, INST: "module\nname\n"
			mod, err1 := readLine(br)
			name, err2 := readLine(br)
			if err1 != nil || err2 != nil {
				return imports, errPickle
			}
			imports = append(imports, mod+"."+name)
			other()
		case 0x93: // STACK_GLOBAL
			if len(strs) >= 2 {
				imports = append(imports, strs[len(strs)-2]+"."+strs[len(strs)-1])
			} else {
				imports = append(imports, "?")
			}
			other()

		// Strings.
		case 'S', 'V': // STRING, UNICODE: text line
			s, err := readLine(br)
			if err != nil {
				return imports, errPickle
			}
			pushStr(strings.Trim(s, `'"`))
		case 'X': // BINUNICODE
			s, err := readStr(br, 4)
			if err != nil {
				return imports, err
			}
			pushStr(s)
		case 0x8c: // SHORT_BINUNICODE
			s, err := readStr(br, 1)
			if err != nil {
				return imports, err
			}
			pushStr(s)
		case 0x8d: // BINUNICODE8
			s, err := readStr(br, 8)
			if err != nil {
				return imports, err
			}
			pushStr(s)

		// Memo.
		case 0x94: // MEMOIZE
			memoize(memoLen)
			memoLen++
		case 'p': // PUT
			line, err := readLine(br)
			if err != nil {
				return imports, errPickle
			}
			var idx uint64
			fmt.Sscan(line, &idx)
			memoize(idx)
		case 'q': // BINPUT
			idx, err := readUint(br, 1)
			if err != nil {
				return imports, err
			}
			memoize(idx)
		case 'r': // LONG_BINPUT
			idx, err := readUint(br, 4)
			if err != nil {
				return imports, err
			}
			memoize(idx)
		case 'g': // GET
			line, err := readLine(br)
			if err != nil {
				return imports, errPickle
			}
			var idx uint64
			fmt.Sscan(line, &idx)
			get(idx)
		case 'h': // BINGET
			idx, err := readUint(br, 1)
			if err != nil {
				return imports, err
			}
			get(idx)
		case 'j': // LONG_BINGET
			idx, err := readUint(br, 4)
			if err != nil {
				return imports, err
			}
			get(idx)

		// Framing; doesn't touch the stack.
		case 0x80: // PROTO
			if _, err := readUint(br, 1); err != nil {
				return imports, err
			}
		case 0x95: // FRAME
			if _, err := readUint(br, 8); err != nil {
				return imports, err
			}

		// Everything else: skip its argument.
		case 'F', 'I', 'L', 'P': // FLOAT, INT, LONG, PERSID: text line
			if _, err := readLine(br); err != nil {
				return imports, errPickle
			}
			other()
		case 'K', 0x82: // BININT1, EXT1
			if err := skip(br, 1); err != nil {
				return imports, err
			}
			other()
		case 'M', 0x83: // BININT2, EXT2
			if err := skip(br, 2); err != nil {
				return imports, err
			}
			other()
		case 'J', 0x84: // BININT, EXT4
			if err := skip(br, 4); err != nil {
				return imports, err
			}
			other()
		case 'G': // BINFLOAT
			if err := skip(br, 8); err != nil {
				return imports, err
			}
			other()
		case 'U', 'C', 0x8a: // SHORT_BINSTRING, SHORT_BINBYTES, LONG1
			if err := skipCounted(br, 1); err != nil {
				return imports, err
			}
			other()
		case 'T', 'B', 0x8b: // BINSTRING, BINBYTES, LONG4
			if err := skipCounted(br, 4); err != nil {
				return imports, err
			}
			other()
		case 0x8e, 0x96: // BINBYTES8, BYTEARRAY8
			if err := skipCounted(br, 8); err != nil {
				return imports, err
			}
			other()
		case '(', '0', '1', '2', 'N', 'Q', 'R', 'a', 'b', 'd', '}', 'e', 'l', ']', 'o', 's', 't', ')', 'u',
			0x81, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8f, 0x90, 0x91, 0x92, 0x97, 0x98:
			// No argument.
			other()
		default:
			return imports, fmt.Errorf("%w: unknown opcode 0x%02x", errPickle, op)
		}
	}
}

const maxPickleLine = 4096

func readLine(br *bufio.Reader) (string, error) {
	var b []byte
	for len(b) < maxPickleLine {
		c, err := br.ReadByte()
		if err != nil {
			return "", err
		}
		if c == '\n' {
			return strings.TrimSuffix(string(b), "\r"), nil
		}
		b = append(b, c)
	}
	return "", errPickle
}

func readUint(br *bufio.Reader, n int) (uint64, error) {
	var buf [8]byte
	if _, err := io.ReadFull(br, buf[:n]); err != nil {
		return 0, errPickle
	}
	return binary.LittleEndian.Uint64(buf[:]), nil
}

func skip(br *bufio.Reader, n int64) error {
	if _, err := br.Discard(int(n)); err != nil {
		return errPickle
	}
	return nil
}

// skipCounted skips a payload preceded by an n-byte little-endian length.
func skipCounted(br *bufio.Reader, n int) error {
	size, err := readUint(br, n)
	if err != nil {
		return err
	}
	if size > 1<<40 {
		return errPickle
	}
	_, err = io.CopyN(io.Discard, br, int64(size))
	if err != nil {
		return errPickle
	}
	return nil
}

const maxPickleString = 1 << 16

func readStr(br *bufio.Reader, n int) (string, error) {
	size, err := readUint(br, n)
	if err != nil {
		return "", err
	}
	if size > maxPickleString {
		// Too long to be a module or attribute name; skip it.
		if _, err := io.CopyN(io.Discard, br, int64(size)); err != nil {
			return "", errPickle
		}
		return "", nil
	}
	buf := make([]byte, size)
	if _, err := io.ReadFull(br, buf); err != nil {
		return "", errPickle
	}
	return string(buf), nil
}

// dangerousImport reports whether loading a pickle that imports imp can run
// commands, code or network calls. The list follows the callables used in
// real malicious models and in picklescan/modelscan's deny lists.
func dangerousImport(imp string) bool {
	if imp == "?" {
		return false
	}
	mod, name := imp, ""
	if i := strings.LastIndex(imp, "."); i >= 0 {
		mod, name = imp[:i], imp[i+1:]
	}
	top, _, _ := strings.Cut(mod, ".")
	switch top {
	case "os", "posix", "nt", "subprocess", "sys", "socket", "shutil", "runpy", "pty",
		"webbrowser", "requests", "httplib", "http", "urllib", "urllib2", "urllib3", "ftplib",
		"smtplib", "telnetlib", "importlib", "pickle", "_pickle", "cPickle", "dill", "code",
		"commands", "ctypes", "multiprocessing", "asyncio", "pip", "platform", "pdb", "bdb",
		"timeit", "venv", "ensurepip", "_posixsubprocess", "aiohttp", "httpx", "paramiko":
		return true
	case "builtins", "__builtin__", "__builtins__":
		switch name {
		case "eval", "exec", "execfile", "compile", "open", "getattr", "setattr", "delattr",
			"__import__", "globals", "locals", "vars", "breakpoint", "input", "apply", "help":
			return true
		}
	case "operator":
		return name == "attrgetter" || name == "methodcaller"
	case "numpy":
		return name == "runstring" || name == "load"
	case "torch":
		return name == "load" || strings.HasPrefix(mod, "torch.hub") || strings.Contains(mod, "_inductor")
	}
	return false
}
