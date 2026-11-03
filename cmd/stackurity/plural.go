package main

import "strconv"

// count is n followed by the noun for one or for many: "1 finding",
// "2 findings", "0 findings".
func count[N int | int64](n N, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.FormatInt(int64(n), 10) + " " + many
}

// agree picks the word that agrees with n: "meets" for 1, "meet" otherwise.
func agree[N int | int64](n N, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
