package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/stackurity/stackurity/internal/client"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/plugins/kubernetes/kube"
)

// Keys of the reporter's Secret.
const (
	secretEnrollCode  = "enroll-code" // put there by the install command
	secretToken       = "token"       // written by the reporter
	secretEnvironment = "environment" // the enrollment code's environment
)

// errNotEnrolled: the reporter has no token and no usable enrollment code
// yet. It waits for one (the Secret may be created after the manifest).
var errNotEnrolled = errors.New("not enrolled")

// notEnrolledPoll is how often a reporter without a token looks at its
// Secret again.
var notEnrolledPoll = 15 * time.Second

func kubernetesReporterCmd() *cobra.Command {
	var server, secretName, clusterName, envName, envLabel, output string
	var namespaces, exclude []string
	var maxImages, imageScans int
	var interval time.Duration
	var once bool
	cmd := &cobra.Command{
		Use:   "kubernetes-reporter",
		Short: "Run in a Kubernetes cluster and report its workloads and images to the server",
		Long: `Runs inside a Kubernetes cluster (deploy it with the stackurity-reporter Helm
chart or the manifest at <server>/install/kubernetes.yaml) and sends the
server what the kubernetes plugin would read: the cluster, its workloads,
the images they run and how they are exposed. It uses the pod's service
account with read-only RBAC, and only connects out: to the cluster's API
server and to Stackurity over HTTPS. No kubeconfig leaves the cluster.

Credentials live in one Secret in the pod's namespace (--secret). The
install command puts a one-time enrollment code in it (key enroll-code); on
first start the reporter exchanges it for a collector token (the same
exchange as stackurity enroll), stores the token there (key token) and
removes the code. Until the Secret has either, the reporter waits. If the
server later refuses the token, put a new code in the Secret as
enroll-code and the reporter enrolls again.

The server scans the images the cluster runs from their registries, as for
the plugin: --image-scans bounds how many one report may queue.

With --output the collection is written to a file instead (no server, no
token needed), to see what would be sent.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := map[string]any{"cluster_name": clusterName, "environment": envName, "environment_label": envLabel, "max_images": maxImages}
			if len(namespaces) > 0 {
				cfg["namespaces"] = namespaces
			}
			if len(exclude) > 0 {
				cfg["exclude_namespaces"] = exclude
			}
			raw, _ := json.Marshal(cfg)
			settings, problems := kube.ParseSettings(raw)
			if len(problems) > 0 {
				return errors.New(strings.Join(problems, "; "))
			}
			if imageScans < 0 || imageScans > 500 {
				return errors.New("--image-scans must be between 0 and 500")
			}
			connect := func(ctx context.Context) (*kube.Client, error) {
				return kube.InCluster(ctx, "stackurity-kubernetes-reporter/"+version)
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			if output != "" {
				kc, err := connect(ctx)
				if err != nil {
					return err
				}
				bs, err := collectCluster(ctx, kc, settings)
				if err != nil {
					return err
				}
				return writeJSON(output, bs)
			}
			if server == "" {
				return errors.New("--server or STACKURITY_SERVER is required")
			}
			if _, err := client.New(server, "", version); err != nil {
				return err
			}
			// The enrollment code and the token cross this connection.
			if !strings.HasPrefix(server, "https://") && os.Getenv("STACKURITY_ALLOW_HTTP") != "1" {
				return errors.New("the server URL must use https (set STACKURITY_ALLOW_HTTP=1 to override)")
			}
			ns, err := kube.PodNamespace()
			if err != nil {
				return fmt.Errorf("the pod's namespace: %w (kubernetes-reporter runs in a Kubernetes pod)", err)
			}
			if interval < time.Minute {
				return errors.New("--interval must be at least 1m")
			}
			r := &k8sReporter{server: strings.TrimRight(server, "/"), secret: secretName, namespace: ns, settings: settings,
				imageScans: imageScans, connect: connect, log: slog.New(slog.NewTextHandler(os.Stderr, nil))}
			if once {
				return r.runOnce(ctx)
			}
			return r.run(ctx, interval)
		},
	}
	f := cmd.Flags()
	f.StringVar(&server, "server", os.Getenv("STACKURITY_SERVER"), "server URL (env STACKURITY_SERVER)")
	f.StringVar(&secretName, "secret", envOr("STACKURITY_REPORTER_SECRET", "stackurity-reporter"), "Secret in the pod's namespace holding the enrollment code and token (env STACKURITY_REPORTER_SECRET)")
	f.StringVar(&clusterName, "cluster-name", os.Getenv("STACKURITY_CLUSTER_NAME"), "name of the cluster asset (env STACKURITY_CLUSTER_NAME; default kubernetes)")
	f.StringVar(&envName, "environment", os.Getenv("STACKURITY_ENVIRONMENT"), "environment of the cluster and its workloads (env STACKURITY_ENVIRONMENT; default: the enrollment code's)")
	f.StringVar(&envLabel, "environment-label", os.Getenv("STACKURITY_ENVIRONMENT_LABEL"), "namespace label whose value is a workload's environment (env STACKURITY_ENVIRONMENT_LABEL)")
	f.StringSliceVar(&namespaces, "namespaces", envList("STACKURITY_NAMESPACES"), "only these namespaces (env STACKURITY_NAMESPACES, comma separated)")
	f.StringSliceVar(&exclude, "exclude-namespaces", envList("STACKURITY_EXCLUDE_NAMESPACES"), "leave these namespaces out (env STACKURITY_EXCLUDE_NAMESPACES)")
	f.IntVar(&maxImages, "max-images", envIntOr("STACKURITY_MAX_IMAGES", 300), "most images reported per run, up to 2000 (env STACKURITY_MAX_IMAGES)")
	f.IntVar(&imageScans, "image-scans", envIntOr("STACKURITY_IMAGE_SCANS", 25), "most image scans one report asks the server for, 0 for none (env STACKURITY_IMAGE_SCANS)")
	f.DurationVar(&interval, "interval", envDurationOr("STACKURITY_INTERVAL", time.Hour), "time between reports (env STACKURITY_INTERVAL)")
	f.BoolVar(&once, "once", false, "report once and exit")
	f.StringVarP(&output, "output", "o", "", "write the collection to this file instead of sending it")
	return cmd
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envList(key string) []string {
	var out []string
	for _, v := range strings.Split(os.Getenv(key), ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func envIntOr(key string, def int) int {
	if n, err := strconv.Atoi(os.Getenv(key)); err == nil {
		return n
	}
	return def
}

func envDurationOr(key string, def time.Duration) time.Duration {
	if d, err := time.ParseDuration(os.Getenv(key)); err == nil {
		return d
	}
	return def
}

// collectCluster reads the cluster with the kubernetes plugin's code.
func collectCluster(ctx context.Context, kc *kube.Client, s kube.Settings) ([]*model.ObservationBatch, error) {
	bs, err := kube.Collect(ctx, kc, s)
	if err != nil {
		return nil, err
	}
	for _, b := range bs {
		b.Collector.Method = "agent"
		if err := b.Validate(); err != nil {
			return nil, fmt.Errorf("%s batch for %s: %w", b.Collector.ID, b.Asset.Name, err)
		}
	}
	return bs, nil
}

// k8sReporter is one reporter's state between runs.
type k8sReporter struct {
	server     string
	secret     string // the Secret's name, in namespace
	namespace  string
	settings   kube.Settings
	imageScans int
	connect    func(ctx context.Context) (*kube.Client, error)
	log        *slog.Logger

	// pending is a token redeemed but not yet stored in the Secret.
	pending, pendingEnv string
	// rejected: the server refused the stored token; a code in the Secret
	// is redeemed again.
	rejected bool
	// refusedCode is a code the server refused, not tried again.
	refusedCode string
	// reportAPI: the server takes POST /kubernetes/report (nil: not asked).
	reportAPI *bool
}

func (r *k8sReporter) run(ctx context.Context, interval time.Duration) error {
	for {
		wait := interval
		err := r.runOnce(ctx)
		switch {
		case ctx.Err() != nil:
			return nil
		case errors.Is(err, errNotEnrolled):
			r.log.Warn("waiting for enrollment", "reason", err.Error())
			wait = notEnrolledPoll
		case err != nil:
			r.log.Error("report failed", "err", err.Error(), "next", interval.String())
			if r.rejected {
				wait = notEnrolledPoll
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
	}
}

func (r *k8sReporter) runOnce(ctx context.Context) error {
	kc, err := r.connect(ctx)
	if err != nil {
		return fmt.Errorf("kubernetes API: %w", err)
	}
	token, env, err := r.credentials(ctx, kc)
	if err != nil {
		return err
	}
	s := r.settings
	if s.Environment == "" {
		s.Environment = env
	}
	bs, err := collectCluster(ctx, kc, s)
	if err != nil {
		return err
	}
	cl, err := client.New(r.server, token, version)
	if err != nil {
		return err
	}
	err = r.send(ctx, cl, bs)
	var ae *client.APIError
	if errors.As(err, &ae) && ae.Status == 401 {
		r.rejected = true
		return fmt.Errorf("the server refused this cluster's token (revoked?): put a new enrollment code in Secret %s/%s as %s and the reporter enrolls again",
			r.namespace, r.secret, secretEnrollCode)
	}
	return err
}

// send reports the batches: in one request where the server takes it,
// else batch by batch (no image scans; servers before kubernetes_report).
func (r *k8sReporter) send(ctx context.Context, cl *client.Client, bs []*model.ObservationBatch) error {
	if r.reportAPI == nil {
		m, err := cl.Meta(ctx)
		if err != nil {
			return fmt.Errorf("server: %w", err)
		}
		has := m.Has(client.FeatureKubernetesReport)
		r.reportAPI = &has
		if !has {
			r.log.Warn("this Stackurity server predates POST /kubernetes/report: batches are sent one by one and the images are not scanned; upgrade the server")
		}
	}
	if *r.reportAPI {
		res, err := cl.KubernetesReport(ctx, bs, r.imageScans)
		if err != nil {
			return err
		}
		r.log.Info("reported", "cluster_asset", res.ClusterAssetID, "assets", res.Assets, "new", res.NewAssets, "images", res.Images,
			"scans_queued", res.ImageScans.Queued, "scans_fresh", res.ImageScans.Fresh, "scans_deferred", res.ImageScans.Deferred)
		if len(res.Refused) > 0 {
			r.log.Warn("assets left out at the organisation's monitored-asset limit", "count", len(res.Refused))
		}
		return nil
	}
	for i, b := range bs {
		if _, err := cl.Ingest(ctx, b); err != nil {
			if i == 0 {
				return err
			}
			r.log.Warn("batch failed", "asset", b.Asset.Name, "err", err.Error())
		}
	}
	r.log.Info("reported", "batches", len(bs))
	return nil
}

// credentials returns the collector token and the enrollment's
// environment: the token in the Secret, or one redeemed with the code in it.
func (r *k8sReporter) credentials(ctx context.Context, kc *kube.Client) (token, env string, err error) {
	sec, err := kc.GetSecret(ctx, r.namespace, r.secret)
	switch {
	case kube.IsNotFound(err):
		return "", "", fmt.Errorf("%w: Secret %s/%s does not exist yet; create it with the enrollment code: kubectl -n %s create secret generic %s --from-literal=%s=enr_...",
			errNotEnrolled, r.namespace, r.secret, r.namespace, r.secret, secretEnrollCode)
	case err != nil:
		return "", "", fmt.Errorf("reading Secret %s/%s: %w", r.namespace, r.secret, err)
	}
	if r.pending != "" {
		// Redeemed earlier, not stored yet: store it now.
		sec.Set(secretToken, r.pending)
		sec.Set(secretEnvironment, r.pendingEnv)
		sec.Set(secretEnrollCode, "")
		if err := kc.UpdateSecret(ctx, sec); err != nil {
			r.log.Error("the token is still not stored in the Secret; it is lost if the pod restarts", "err", err.Error())
		} else {
			r.pending = ""
		}
		return sec.Get(secretToken), sec.Get(secretEnvironment), nil
	}
	tok, code := sec.Get(secretToken), sec.Get(secretEnrollCode)
	if tok != "" && !r.rejected {
		return tok, sec.Get(secretEnvironment), nil
	}
	if code == "" || code == r.refusedCode {
		why := "it has no " + secretToken + " and no " + secretEnrollCode
		if code != "" {
			why = "the server refused its " + secretEnrollCode
		} else if r.rejected {
			why = "the server refused its token"
		}
		return "", "", fmt.Errorf("%w: Secret %s/%s: %s; put a new code from Integrations > Kubernetes in it as %s",
			errNotEnrolled, r.namespace, r.secret, why, secretEnrollCode)
	}
	// The code can be used once: make sure the token can be stored before
	// using it up (an update that changes nothing).
	if err := kc.UpdateSecret(ctx, sec); err != nil {
		return "", "", fmt.Errorf("the reporter cannot update Secret %s/%s, so the code was not used: %w", r.namespace, r.secret, err)
	}
	cl, err := client.New(r.server, "", version)
	if err != nil {
		return "", "", err
	}
	name := r.settings.ClusterName
	if name == "" {
		name = "kubernetes"
	}
	e, err := cl.Enroll(ctx, code, "Kubernetes cluster "+name, 0)
	var ae *client.APIError
	if errors.As(err, &ae) && ae.Status == 403 {
		r.refusedCode = code
		return "", "", fmt.Errorf("%w: the server refused the enrollment code (used, expired or revoked); put a new one in Secret %s/%s as %s",
			errNotEnrolled, r.namespace, r.secret, secretEnrollCode)
	}
	if err != nil {
		return "", "", fmt.Errorf("enrolling: %w", err)
	}
	r.rejected, r.refusedCode = false, ""
	for attempt := 0; ; attempt++ {
		sec.Set(secretToken, e.Token)
		sec.Set(secretEnvironment, e.Environment)
		sec.Set(secretEnrollCode, "")
		err = kc.UpdateSecret(ctx, sec)
		if !kube.IsConflict(err) || attempt == 3 {
			break
		}
		// Changed meanwhile (kubectl, Helm): apply the token to the new version.
		if sec, err = kc.GetSecret(ctx, r.namespace, r.secret); err != nil {
			break
		}
	}
	if err != nil {
		r.pending, r.pendingEnv = e.Token, e.Environment
		r.log.Error("enrolled, but the token could not be stored in the Secret; retrying on the next run", "err", err.Error())
	} else {
		r.log.Info("enrolled; the token is stored in the Secret and the code removed", "secret", r.namespace+"/"+r.secret)
	}
	return e.Token, e.Environment, nil
}
