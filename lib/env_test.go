package lib

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetVproxPasswords(t *testing.T) {
	tests := []struct {
		name      string
		password  string
		passwords string
		want      []string
		wantErr   string
	}{
		{name: "missing", wantErr: "VPROX_PASSWORD or VPROX_PASSWORDS environment variable must be set"},
		{name: "legacy", password: "old", want: []string{"old"}},
		{name: "literal legacy", password: " old,password ", want: []string{" old,password "}},
		{name: "single entry", passwords: "new", want: []string{"new"}},
		{name: "multiple", passwords: "first,second,third", want: []string{"first", "second", "third"}},
		{name: "both", password: "old", passwords: "new,next", want: []string{"old", "new", "next"}},
		{name: "trim entries", passwords: " first ,\tsecond\n,third with spaces ", want: []string{"first", "second", "third with spaces"}},
		{name: "duplicates", password: "same", passwords: "same,same", want: []string{"same", "same", "same"}},
		{name: "blank", passwords: " \t\n", wantErr: "VPROX_PASSWORDS must not contain empty passwords"},
		{name: "leading comma", passwords: ",new", wantErr: "VPROX_PASSWORDS must not contain empty passwords"},
		{name: "trailing comma", passwords: "new,", wantErr: "VPROX_PASSWORDS must not contain empty passwords"},
		{name: "empty entry", passwords: "first,,second", wantErr: "VPROX_PASSWORDS must not contain empty passwords"},
		{name: "blank entry", passwords: "first, ,second", wantErr: "VPROX_PASSWORDS must not contain empty passwords"},
		{name: "invalid list with legacy", password: "old", passwords: "new,", wantErr: "VPROX_PASSWORDS must not contain empty passwords"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("VPROX_PASSWORD", tt.password)
			t.Setenv("VPROX_PASSWORDS", tt.passwords)
			got, err := GetVproxPasswords()
			if tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
				assert.Nil(t, got)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGetVproxPasswordRemainsSingle(t *testing.T) {
	t.Setenv("VPROX_PASSWORDS", "first,second")
	t.Setenv("VPROX_PASSWORD", " literal,password ")
	got, err := GetVproxPassword()
	assert.NoError(t, err)
	assert.Equal(t, " literal,password ", got)

	t.Setenv("VPROX_PASSWORD", "")
	_, err = GetVproxPassword()
	assert.EqualError(t, err, "VPROX_PASSWORD environment variable is not set")
}
