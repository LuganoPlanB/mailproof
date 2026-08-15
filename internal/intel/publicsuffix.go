package intel

// PublicSuffixListModule and PublicSuffixListModuleChecksum identify the
// offline PSL implementation used by RegistrableDomain. The module is pinned
// in go.mod and its checksum is enforced by go.sum; normalization never fetches
// PSL data, performs DNS, or consults an external service.
const (
	PublicSuffixListModule   = "golang.org/x/net@v0.56.0"
	PublicSuffixListChecksum = "h1:Rw8j/hFzGvJUZwNBXnAtf5sVDVt+65SK2C7IxCxZt5o="
	PublicSuffixListLicense  = "BSD-3-Clause (golang.org/x/net; see module LICENSE)"
)
