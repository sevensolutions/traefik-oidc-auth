package redisclient

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// reply is a decoded RESP2 reply. Only the subset of the protocol this client actually needs
// (simple strings, errors, integers, bulk strings, arrays, and nils) is represented.
type reply struct {
	str     string
	isNil   bool
	isErr   bool
	isArray bool
	array   []reply
}

// writeCommand writes args as a RESP2 array of bulk strings - the standard way Redis clients
// send commands - and flushes it.
func writeCommand(w *bufio.Writer, args ...string) error {
	if _, err := fmt.Fprintf(w, "*%d\r\n", len(args)); err != nil {
		return err
	}
	for _, arg := range args {
		if _, err := fmt.Fprintf(w, "$%d\r\n%s\r\n", len(arg), arg); err != nil {
			return err
		}
	}
	return w.Flush()
}

// readReply decodes a single RESP2 reply, recursing for arrays.
func readReply(r *bufio.Reader) (reply, error) {
	line, err := readLine(r)
	if err != nil {
		return reply{}, err
	}
	if len(line) == 0 {
		return reply{}, fmt.Errorf("redis: received empty reply line")
	}

	prefix, body := line[0], line[1:]

	switch prefix {
	case '+': // simple string
		return reply{str: body}, nil
	case '-': // error
		return reply{str: body, isErr: true}, nil
	case ':': // integer
		return reply{str: body}, nil
	case '$': // bulk string
		n, err := strconv.Atoi(body)
		if err != nil {
			return reply{}, fmt.Errorf("redis: invalid bulk string length %q: %w", body, err)
		}
		if n < 0 {
			return reply{isNil: true}, nil
		}
		buf := make([]byte, n+2) // payload + trailing \r\n
		if _, err := io.ReadFull(r, buf); err != nil {
			return reply{}, err
		}
		return reply{str: string(buf[:n])}, nil
	case '*': // array
		n, err := strconv.Atoi(body)
		if err != nil {
			return reply{}, fmt.Errorf("redis: invalid array length %q: %w", body, err)
		}
		if n < 0 {
			return reply{isNil: true, isArray: true}, nil
		}
		items := make([]reply, n)
		for i := 0; i < n; i++ {
			item, err := readReply(r)
			if err != nil {
				return reply{}, err
			}
			items[i] = item
		}
		return reply{isArray: true, array: items}, nil
	default:
		return reply{}, fmt.Errorf("redis: unrecognized reply type %q", string(prefix))
	}
}

func readLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}
