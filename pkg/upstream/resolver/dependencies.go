package resolver

// DependencyProvider exposes direct resolver edges for startup validation.
// Implementations must not resolve queries or initialize network resources here.
type DependencyProvider interface {
	ResolverDependencies() []Resolver
}
