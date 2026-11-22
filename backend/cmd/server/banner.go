package main

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// woodpecker is the ASCII bird shown by `serve` and `version`: crest, barred wing (=) and
// the beak on the trunk (||). {r}...{d} marks what turns red on a terminal (crest and the
// "knock" text); the markers are stripped otherwise.
var woodpecker = []string{
	`    {r},/\{d}          ||`,
	`   /  o\========>||`,
	`   \   /   {r}knock{d} ||`,
	`    |=|    {r}knock{d} ||`,
	`    |=|          ||`,
	`    /_\          ||`,
}

// printWoodpecker writes the bird with the given text lines to its right (top aligned
// from the second row, next to the beak).
func printWoodpecker(w io.Writer, text ...string) {
	color := useColor(w)
	for i, line := range woodpecker {
		if color {
			line = strings.NewReplacer("{r}", "\x1b[31m", "{d}", "\x1b[0m").Replace(line)
		} else {
			line = strings.NewReplacer("{r}", "", "{d}", "").Replace(line)
		}
		if j := i - 1; j >= 0 && j < len(text) && text[j] != "" {
			line += "   " + text[j]
		}
		fmt.Fprintln(w, "  "+line)
	}
}

// useColor reports whether w is a character device, with NO_COLOR (no-color.org) unset and
// TERM not dumb.
func useColor(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
