package dotseal

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	Version      = "v1"
	DefaultScope = "default"
	NonceLen     = 12
	KeyLen       = 32
)

var (
	hexKeyPattern    = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	namePattern      = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	scopeSealPattern = regexp.MustCompile(`^[A-Za-z0-9_.\-]+$`)
	aadInjectPattern = regexp.MustCompile(`[\n\r]`)
)

// IsSafeEnvName reports whether `name` is a valid dotenv variable name per
// the dotseal CLI / dotenv convention. Reserved JavaScript prototype names
// are rejected for cross-language portability.
func IsSafeEnvName(name string) bool {
	if !namePattern.MatchString(name) {
		return false
	}
	switch name {
	case "__proto__", "constructor", "prototype":
		return false
	}
	return true
}

// IsValidScope reports whether `scope` is a valid dotseal scope at seal-time.
func IsValidScope(scope string) bool {
	return scopeSealPattern.MatchString(scope)
}

func IsEncryptedValue(value string) bool {
	return strings.HasPrefix(value, "enc:")
}

func ParseKey(raw string) ([]byte, error) {
	text := strings.TrimSpace(raw)
	if hexKeyPattern.MatchString(text) {
		key, err := hex.DecodeString(text)
		if err != nil {
			return nil, fmt.Errorf("parse hex key: %w", err)
		}
		return key, nil
	}

	key, err := decodeBase64URL(text)
	if err != nil {
		return nil, fmt.Errorf("parse base64url key: %w", err)
	}
	if len(key) != KeyLen {
		return nil, fmt.Errorf("dotseal key must decode to %d bytes", KeyLen)
	}
	return key, nil
}

func DecryptValue(value string, key []byte, scope string, name string) (string, error) {
	if !IsEncryptedValue(value) {
		return value, nil
	}
	if scope == "" {
		return "", fmt.Errorf("dotseal DecryptValue requires scope")
	}
	if name == "" {
		return "", fmt.Errorf("dotseal DecryptValue requires name")
	}
	if aadInjectPattern.MatchString(name) {
		return "", fmt.Errorf("dotseal DecryptValue: invalid name")
	}
	if aadInjectPattern.MatchString(scope) {
		return "", fmt.Errorf("dotseal DecryptValue: invalid scope")
	}
	if len(key) != KeyLen {
		return "", fmt.Errorf("dotseal key must be %d bytes", KeyLen)
	}

	parts := strings.SplitN(value, ":", 3)
	if len(parts) != 3 || parts[0] != "enc" || parts[1] != Version {
		return "", fmt.Errorf("unsupported dotseal value")
	}

	payload, err := decodeBase64URL(parts[2])
	if err != nil {
		return "", fmt.Errorf("decode encrypted value for %s: %w", name, err)
	}
	if len(payload) <= NonceLen {
		return "", fmt.Errorf("dotseal value for %s is too short", name)
	}
	nonce := payload[:NonceLen]
	ciphertext := payload[NonceLen:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create gcm: %w", err)
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, []byte(aad(scope, name)))
	if err != nil {
		return "", fmt.Errorf("decrypt failed for %s: %w", name, err)
	}
	if !utf8.Valid(plaintext) {
		return "", fmt.Errorf("plaintext for %s is not utf8", name)
	}
	return string(plaintext), nil
}

func DecryptEnv(env map[string]string, key []byte, scope string) (map[string]string, error) {
	out := make(map[string]string, len(env))
	for name, value := range env {
		decrypted, err := DecryptValue(value, key, scope, name)
		if err != nil {
			return nil, err
		}
		out[name] = decrypted
	}
	return out, nil
}

func ParseEnv(content string) map[string]string {
	env := map[string]string{}
	content = strings.TrimPrefix(content, "\ufeff")
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimLeft(line, " \t\ufeff")
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		rest := stripExportPrefix(trimmed)
		idx := strings.Index(rest, "=")
		if idx == -1 {
			continue
		}
		name := strings.TrimSpace(rest[:idx])
		if namePattern.MatchString(name) {
			env[name] = ParseEnvValue(rest[idx+1:])
		}
	}
	return env
}

func stripExportPrefix(line string) string {
	if !strings.HasPrefix(line, "export") {
		return line
	}
	after := line[len("export"):]
	if len(after) == 0 || (after[0] != ' ' && after[0] != '\t') {
		return line
	}
	return strings.TrimLeft(after, " \t")
}

func ParseEnvValue(raw string) string {
	trimmedStart := strings.TrimLeft(raw, " \t\r\n\ufeff")
	if strings.HasPrefix(trimmedStart, `"`) {
		rest := trimmedStart[1:]
		if end := findDoubleQuoteEnd(rest); end != -1 {
			return unescapeDoubleQuoted(rest[:end])
		}
	} else if strings.HasPrefix(trimmedStart, `'`) {
		if end := strings.Index(trimmedStart[1:], `'`); end != -1 {
			return trimmedStart[1 : 1+end]
		}
	}
	return strings.TrimRight(stripInlineComment(trimmedStart), " \t\r\n")
}

func stripInlineComment(value string) string {
	for i := 0; i < len(value); i++ {
		if value[i] == '#' && (i == 0 || value[i-1] == ' ' || value[i-1] == '\t') {
			return value[:i]
		}
	}
	return value
}

func findDoubleQuoteEnd(rest string) int {
	for i := 0; i < len(rest); i++ {
		if rest[i] == '\\' && i+1 < len(rest) {
			i++
			continue
		}
		if rest[i] == '"' {
			return i
		}
	}
	return -1
}

// aad constructs the AAD payload `dotseal:v1\nscope=<scope>\nname=<NAME>\n`.
// See FORMAT.md § Algorithm. `scope` and `name` MUST be validated against
// the AAD-injection charset (no \n/\r) before reaching this — DecryptValue
// does that above.
func aad(scope string, name string) string {
	return fmt.Sprintf("dotseal:%s\nscope=%s\nname=%s\n", Version, scope, name)
}

func decodeBase64URL(value string) ([]byte, error) {
	if strings.Contains(value, "=") {
		return base64.URLEncoding.DecodeString(value)
	}
	return base64.RawURLEncoding.DecodeString(value)
}

func unescapeDoubleQuoted(value string) string {
	var out strings.Builder
	out.Grow(len(value))
	escaping := false
	for _, ch := range value {
		if !escaping {
			if ch == '\\' {
				escaping = true
			} else {
				out.WriteRune(ch)
			}
			continue
		}

		switch ch {
		case 'n':
			out.WriteByte('\n')
		case 'r':
			out.WriteByte('\r')
		case 't':
			out.WriteByte('\t')
		case '"', '\\':
			out.WriteRune(ch)
		default:
			out.WriteByte('\\')
			out.WriteRune(ch)
		}
		escaping = false
	}
	if escaping {
		out.WriteByte('\\')
	}
	return out.String()
}
