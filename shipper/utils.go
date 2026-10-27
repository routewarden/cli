package shipper

import (
	"flag"
	"strings"
)

type StringSlice []string

func (s *StringSlice) String() string {
	return strings.Join(*s, ", ")
}

func (s *StringSlice) Set(val string) error {
	*s = append(*s, val)
	return nil
}

// splitArgs splits a string by whitespace while preserving single- and double-quoted blocks.
func splitArgs(s string) []string {
	var tokens []string
	var cur strings.Builder
	inSingle := false
	inDouble := false

	for i := 0; i < len(s); i++ {
		r := s[i]
		if r == '\'' && !inDouble {
			inSingle = !inSingle
			continue
		}
		if r == '"' && !inSingle {
			inDouble = !inDouble
			continue
		}
		if (r == ' ' || r == '\t' || r == '\n') && !inSingle && !inDouble {
			if cur.Len() > 0 {
				tokens = append(tokens, cur.String())
				cur.Reset()
			}
			continue
		}
		cur.WriteByte(r)
	}
	if cur.Len() > 0 {
		tokens = append(tokens, cur.String())
	}
	return tokens
}

func ParseFlagsLenient(fs *flag.FlagSet, args []string) error {
	var expandedArgs []string
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") && (strings.Contains(arg, " -") || strings.Contains(arg, "\t-")) {
			expandedArgs = append(expandedArgs, splitArgs(arg)...)
		} else {
			expandedArgs = append(expandedArgs, arg)
		}
	}
	args = expandedArgs

	var flagArgs []string
	var posArgs []string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			posArgs = append(posArgs, args[i+1:]...)
			break
		}
		if strings.HasPrefix(arg, "-") && arg != "-" {
			name := strings.TrimLeft(arg, "-")
			if strings.Contains(name, "=") {
				flagArgs = append(flagArgs, arg)
				continue
			}
			if name == "help" || name == "h" {
				flagArgs = append(flagArgs, arg)
				continue
			}
			f := fs.Lookup(name)
			if f != nil {
				if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
					flagArgs = append(flagArgs, arg)
					continue
				}
				flagArgs = append(flagArgs, arg)
				if i+1 < len(args) {
					flagArgs = append(flagArgs, args[i+1])
					i++
				}
				continue
			}
			flagArgs = append(flagArgs, arg)
		} else {
			posArgs = append(posArgs, arg)
		}
	}

	reordered := append(flagArgs, posArgs...)
	return fs.Parse(reordered)
}
