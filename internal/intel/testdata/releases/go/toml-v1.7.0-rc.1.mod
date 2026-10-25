// Deprecated: use github.com/BurntSushi/toml/v2 instead.
module github.com/BurntSushi/toml

go 1.18

retract (
	v1.6.0 // Decodes nested tables incorrectly.
	[v0.1.0, v0.2.0]
)
