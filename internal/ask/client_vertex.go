//go:build ask_vertex

package ask

// Vertex AI support, only in builds with the ask_vertex tag: Google's
// client libraries add about 19 MB to the binary, for a provider few
// installations use.

import (
	"context"

	"github.com/anthropics/anthropic-sdk-go/v2"
	"github.com/anthropics/anthropic-sdk-go/v2/option"
	"github.com/anthropics/anthropic-sdk-go/v2/vertex"
)

func init() {
	vertexClient = func(ctx context.Context, cfg Config, opts []option.RequestOption) (anthropic.BetaMessageService, error) {
		cl := anthropic.NewClient(append([]option.RequestOption{vertex.WithGoogleAuth(ctx, cfg.VertexRegion, cfg.VertexProject)}, opts...)...)
		return cl.Beta.Messages, nil
	}
}
