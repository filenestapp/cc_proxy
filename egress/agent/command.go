package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

// splitCommand splits a command line like Python's shlex.split: whitespace separates words; single quotes are
// literal; inside double quotes a backslash escapes " \ $ `; elsewhere a backslash escapes the next character.
func splitCommand(s string) ([]string, error) {
	var words []string
	var cur strings.Builder
	inWord := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\'':
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				return nil, errors.New("unterminated single quote")
			}
			cur.WriteString(s[i+1 : i+1+j])
			i += j + 1
			inWord = true
		case c == '"':
			i++
			for ; i < len(s) && s[i] != '"'; i++ {
				if s[i] == '\\' && i+1 < len(s) && strings.IndexByte("\"\\$`", s[i+1]) >= 0 {
					i++
				}
				cur.WriteByte(s[i])
			}
			if i >= len(s) {
				return nil, errors.New("unterminated double quote")
			}
			inWord = true
		case c == '\\':
			if i+1 < len(s) {
				i++
				cur.WriteByte(s[i])
			}
			inWord = true
		case c == ' ' || c == '\t' || c == '\n':
			if inWord {
				words = append(words, cur.String())
				cur.Reset()
				inWord = false
			}
		default:
			cur.WriteByte(c)
			inWord = true
		}
	}
	if inWord {
		words = append(words, cur.String())
	}
	if len(words) == 0 {
		return nil, errors.New("empty command")
	}
	return words, nil
}

// runCommand runs a --reload-cmd / --status-cmd (no shell) and returns its error, if any.
func runCommand(line string, output io.Writer) error {
	argv, err := splitCommand(line)
	if err != nil {
		return err
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	if output == nil {
		output = os.Stderr
	}
	cmd.Stdout, cmd.Stderr = output, output
	return cmd.Run()
}

// runCommandTimeout is runCommand bounded by timeout: a hung service manager must not stall the agent's cycle. The
// command is killed at the deadline, and output pipes are abandoned shortly after (a child that keeps them open).
func runCommandTimeout(line string, output io.Writer, timeout time.Duration) error {
	argv, err := splitCommand(line)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	if output == nil {
		output = os.Stderr
	}
	cmd.Stdout, cmd.Stderr = output, output
	cmd.WaitDelay = 2 * time.Second
	err = cmd.Run()
	if ctx.Err() != nil {
		return fmt.Errorf("timed out after %s", timeout)
	}
	return err
}
