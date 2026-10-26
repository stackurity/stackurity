package intel

import "testing"

// TestLinksStayOnTheRegistryHost: links inside registry and repository
// documents (NuGet registration pages, the updateinfo location) are
// followed only to the same scheme and host.
func TestLinksStayOnTheRegistryHost(t *testing.T) {
	base := "https://api.nuget.org/v3/registration5-gz-semver2/x/index.json"
	for u, want := range map[string]bool{
		"https://api.nuget.org/v3/registration5-gz-semver2/x/page/1.json": true,
		"https://API.NUGET.ORG/v3/page.json":                              true,
		"http://api.nuget.org/v3/page.json":                               false,
		"https://api.nuget.org.evil.example/page.json":                    false,
		"https://api.nuget.org@evil.example/page.json":                    false,
		"https://evil.example/https://api.nuget.org/":                     false,
		"//evil.example/page.json":                                        false,
		"https://169.254.169.254/latest/meta-data/":                       false,
		"https://api.nuget.org:8443/page.json":                            false,
		"file:///etc/passwd":                                              false,
		"%zz":                                                             false,
	} {
		if got := sameOrigin(u, base); got != want {
			t.Errorf("sameOrigin(%q) = %v", u, got)
		}
	}
	mirror := "https://cdn.amazonlinux.com/al2023/core/mirrors/latest/x86_64/mirror.list"
	for u, want := range map[string]bool{
		"https://cdn.amazonlinux.com/al2023/core/guids/x/repodata/repomd.xml": true,
		"https://cdn.amazonlinux.com.evil.example/repomd.xml":                 false,
		"http://cdn.amazonlinux.com/repomd.xml":                               false,
		"https://user@cdn.amazonlinux.com.evil.example/":                      false,
		"https://10.0.0.1/repomd.xml":                                         false,
	} {
		if got := sameHost(u, mirror); got != want {
			t.Errorf("sameHost(%q) = %v", u, got)
		}
	}
}
