package data

import (
	"log"
	"regexp"
)

func RegexGetBool(expected_output string, output string) bool {
	re, err := regexp.Compile(expected_output)
	if err != nil {
		log.Fatal(err)
	}
	found := re.MatchString(output)
	return found
}
