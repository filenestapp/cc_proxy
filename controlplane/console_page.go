package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
)

//go:embed console.html
var consoleHTML []byte

//go:embed locales/zh-Hans.json
var consoleChinese []byte

const consoleLocaleElement = `<script id="console-zh-hans" type="application/json">`

var consolePage = embedConsoleLocale(consoleHTML, consoleChinese)

func embedConsoleLocale(page, catalog []byte) []byte {
	// Marshal escapes HTML-sensitive characters even inside RawMessage. The
	// translations are data in an inert script element.
	encoded, err := json.Marshal(json.RawMessage(catalog))
	if err != nil {
		panic("invalid console locale: " + err.Error())
	}
	placeholder := []byte(consoleLocaleElement + "{}" + "</script>")
	element := []byte(consoleLocaleElement + string(encoded) + "</script>")
	return bytes.Replace(page, placeholder, element, 1)
}
