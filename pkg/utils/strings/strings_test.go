package strings_test

import (
	"testing"

	"github.com/khulnasoft-lab/tunnel-db/pkg/utils/strings"
	"github.com/stretchr/testify/assert"
)

func TestUnique(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  []string
	}{
		{

			name: "positive test",
			input: []string{
				"test string 1",
				"test string 3",
				"test string 2",
				"test string 1",
				"test string 2",
				"test string 3",
			},
			want: []string{
				"test string 1",
				"test string 2",
				"test string 3",
			},
		},
		{
			name:  "positive test input empty",
			input: []string{},
		},
		{
			name: "positive test input uniq",
			input: []string{
				"test string 1",
				"test string 3",
				"test string 2",
			},
			want: []string{
				"test string 1",
				"test string 2",
				"test string 3",
			},
		},
	}
	for _, tt := range tests {
		actualData := strings.Unique(tt.input)
		assert.Equal(t, actualData, tt.want, tt.name)
	}

}
