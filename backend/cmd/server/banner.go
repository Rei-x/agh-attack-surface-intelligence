package main

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// woodpecker is the compact ASCII bird shown by `serve` and `version`: crest, barred
// wing (=) and the beak on the trunk (||), stuk stuk. {r}...{d} marks what turns red on a
// terminal (crest and the knocking); the markers are stripped otherwise.
var woodpecker = []string{
	`    {r},/\{d}          ||`,
	`   /  o\========>||`,
	`   \   /   {r}stuk{d}  ||`,
	`    |=|    {r}stuk{d}  ||`,
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

// useColor: only on a character device, and never when NO_COLOR is set (no-color.org).
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
