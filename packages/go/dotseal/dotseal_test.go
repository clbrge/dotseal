package dotseal

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

type vectorFile struct {
	Key     string       `json:"key"`
	Cases   []vectorCase `json:"cases"`
	Rejects []vectorCase `json:"rejects"`
}

type vectorCase struct {
	ID        string `json:"id"`
	Scope     string `json:"scope"`
	Name      string `json:"name"`
	Plaintext string `json:"plaintext"`
	Sealed    string `json:"sealed"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve test file path")
	}
	path := filepath.Join(filepath.Dir(file), "..", "..", "..", "test-vectors", "v1.json")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	var vectors vectorFile
	if err := json.Unmarshal(content, &vectors); err != nil {
		t.Fatal(err)
	}
	return vectors
}

func TestDecryptsVectors(t *testing.T) {
	vectors := loadVectors(t)
	key, err := ParseKey(vectors.Key)
	if err != nil {
		t.Fatal(err)
	}

	for _, vector := range vectors.Cases {
		t.Run(vector.ID, func(t *testing.T) {
			got, err := DecryptValue(vector.Sealed, key, vector.Scope, vector.Name)
			if err != nil {
				t.Fatal(err)
			}
			if got != vector.Plaintext {
				t.Fatalf("got %q, want %q", got, vector.Plaintext)
			}
		})
	}
}

func TestRejectsInvalidVectors(t *testing.T) {
	vectors := loadVectors(t)
	key, err := ParseKey(vectors.Key)
	if err != nil {
		t.Fatal(err)
	}

	for _, vector := range vectors.Rejects {
		t.Run(vector.ID, func(t *testing.T) {
			if _, err := DecryptValue(vector.Sealed, key, vector.Scope, vector.Name); err == nil {
				t.Fatal("accepted invalid vector")
			}
		})
	}
}

func TestAcceptsPaddedBase64URL(t *testing.T) {
	vectors := loadVectors(t)
	primary := vectors.Cases[0]
	key, err := ParseKey(vectors.Key + "=")
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecryptValue(primary.Sealed+"==", key, primary.Scope, primary.Name)
	if err != nil {
		t.Fatal(err)
	}
	if got != primary.Plaintext {
		t.Fatalf("got %q, want %q", got, primary.Plaintext)
	}
}

func TestParseAndDecryptEnv(t *testing.T) {
	vectors := loadVectors(t)
	primary := vectors.Cases[0]
	key, err := ParseKey(vectors.Key)
	if err != nil {
		t.Fatal(err)
	}
	env := ParseEnv(primary.Name + "=" + primary.Sealed + "\nPLAIN=value\n")
	got, err := DecryptEnv(env, key, primary.Scope)
	if err != nil {
		t.Fatal(err)
	}
	if got[primary.Name] != primary.Plaintext {
		t.Fatalf("%s got %q", primary.Name, got[primary.Name])
	}
	if got["PLAIN"] != "value" {
		t.Fatalf("PLAIN got %q", got["PLAIN"])
	}
}

func TestParseQuotedDotenvValues(t *testing.T) {
	env := ParseEnv("PLAIN= value \nDOUBLE=\" hello world \"\nSINGLE=' keep spaces '\nESCAPED=\"line\\nnext\\t\\\"q\\\"\"\n")
	if env["PLAIN"] != "value" {
		t.Fatalf("PLAIN got %q", env["PLAIN"])
	}
	if env["DOUBLE"] != " hello world " {
		t.Fatalf("DOUBLE got %q", env["DOUBLE"])
	}
	if env["SINGLE"] != " keep spaces " {
		t.Fatalf("SINGLE got %q", env["SINGLE"])
	}
	if env["ESCAPED"] != "line\nnext\t\"q\"" {
		t.Fatalf("ESCAPED got %q", env["ESCAPED"])
	}
}
