// Package eedeps keeps the licensed edition's third-party modules in this
// repository's go.mod. The stackurity-pro files are added to the build with
// an overlay (tools/eeoverlay), so go mod tidy and Dependabot cannot see
// their imports here and would otherwise drop those modules, which breaks
// the licensed build. deps.go imports them under a build tag nobody sets:
// go mod tidy still counts it, but no binary includes it.
//
// When stackurity-pro starts or stops using a module, update deps.go in the
// same change.
package eedeps
