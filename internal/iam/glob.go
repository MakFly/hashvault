package iam

// matchGlob reports whether s matches pattern, where '*' matches any
// sequence of characters (including ':' and '/') and '?' exactly one.
// There is no escape character and no character class. It works on runes,
// runs in O(len(pattern) * len(s)) at worst and never recurses, so a
// hostile pattern cannot blow the stack.
func matchGlob(pattern, s string) bool {
	p, str := []rune(pattern), []rune(s)
	pi, si := 0, 0
	star, mark := -1, 0
	for si < len(str) {
		switch {
		case pi < len(p) && (p[pi] == '?' || p[pi] == str[si]):
			pi++
			si++
		case pi < len(p) && p[pi] == '*':
			star, mark = pi, si
			pi++
		case star >= 0:
			mark++
			pi, si = star+1, mark
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}
