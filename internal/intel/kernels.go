package intel

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/package-url/packageurl-go"

	"github.com/stackurity/stackurity/internal/osv"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/version"
)

// Kernel packages are reported per installed kernel version, not per binary
// package. An Ubuntu host keeps the image, modules, extra modules and tools
// of every installed kernel, all built from one source package; each is
// matched against the same few thousand kernel advisories, so one CVE
// appeared once per package and the list repeated it. The rules:
//
//   - Packages with no running code (headers, build trees, documentation,
//     source, linux-libc-dev, kernel-headers, kernel-devel) get no findings:
//     a kernel vulnerability is in code they do not contain.
//   - The packages with kernel code of one kernel version on one asset are
//     matched as before, and their findings are merged into one per issue,
//     reported on the package that boots (linux-image-*, kernel-core,
//     kernel, kernel-default), with the other packages listed in evidence.
//   - A kernel version that is installed but not running keeps its findings,
//     marked not_running_kernel, which the risk engine ranks low and the
//     action plan groups under "remove old kernels".

// kernelSlot says how one inventory row takes part in kernel reporting.
type kernelSlot struct {
	role    osv.KernelRole
	group   string // asset, package type and kernel release
	release string
	rep     store.EvalRow // the row findings are reported on
	repName string
	members []string // the version's packages with kernel code
}

// planKernels classifies the kernel packages among rows and picks, for each
// installed kernel version, the package its findings are reported on.
func planKernels(rows []store.EvalRow) map[int64]*kernelSlot {
	out := map[int64]*kernelSlot{}
	type member struct {
		row  store.EvalRow
		name string
	}
	groups := map[string][]member{}
	for _, r := range rows {
		if r.Type != "deb" && r.Type != "rpm" {
			continue
		}
		pu, err := packageurl.FromString(r.Purl)
		if err != nil {
			continue
		}
		role, release := osv.KernelPackage(r.Type, pu.Name, r.Version)
		switch {
		case role == osv.KernelNoCode:
			out[r.InventoryID] = &kernelSlot{role: role, release: release}
		case role == osv.KernelCode && release != "":
			g := fmt.Sprintf("%d|%s|%s", r.AssetID, r.Type, release)
			groups[g] = append(groups[g], member{r, pu.Name})
		}
	}
	for g, ms := range groups {
		sort.Slice(ms, func(i, j int) bool {
			ri, rj := kernelRank(ms[i].row.Type, ms[i].name), kernelRank(ms[j].row.Type, ms[j].name)
			if ri != rj {
				return ri < rj
			}
			return ms[i].name < ms[j].name
		})
		s := &kernelSlot{role: osv.KernelCode, group: g, rep: ms[0].row, repName: ms[0].name}
		_, s.release = osv.KernelPackage(ms[0].row.Type, ms[0].name, ms[0].row.Version)
		for _, m := range ms {
			s.members = appendUnique(s.members, m.name)
		}
		sort.Strings(s.members)
		for _, m := range ms {
			out[m.row.InventoryID] = s
		}
	}
	return out
}

// kernelRank orders the packages of one kernel version: the one that boots
// first, then modules, then anything else.
func kernelRank(purlType, name string) int {
	if purlType == "deb" {
		switch {
		case strings.HasPrefix(name, "linux-image-unsigned-"):
			return 1
		case strings.HasPrefix(name, "linux-image-"):
			return 0
		case strings.HasPrefix(name, "linux-modules-extra-"):
			return 3
		case strings.HasPrefix(name, "linux-modules-"):
			return 2
		}
		return 4
	}
	switch {
	case strings.HasSuffix(name, "-core"):
		return 0
	case strings.Contains(name, "-modules"), strings.HasSuffix(name, "-extra"), strings.HasSuffix(name, "-base"), strings.HasSuffix(name, "-optional"):
		return 2
	}
	return 1 // kernel, kernel-default, kernel-rt, kernel-uek
}

// withKernelSiblings adds, for a partial evaluation, the other kernel
// packages on the same assets, so each kernel version is reported from all
// of its packages whichever ones changed.
func (e *Evaluator) withKernelSiblings(ctx context.Context, rows []store.EvalRow) ([]store.EvalRow, error) {
	have := map[int64]bool{}
	var assets []int64
	seen := map[int64]bool{}
	for _, r := range rows {
		have[r.InventoryID] = true
		if isKernelRow(r) && !seen[r.AssetID] {
			seen[r.AssetID] = true
			assets = append(assets, r.AssetID)
		}
	}
	for _, a := range assets {
		all, err := e.Store.EvalRows(ctx, nil, a)
		if err != nil {
			return nil, err
		}
		for _, r := range all {
			if !have[r.InventoryID] && isKernelRow(r) {
				have[r.InventoryID] = true
				rows = append(rows, r)
			}
		}
	}
	return rows, nil
}

func isKernelRow(r store.EvalRow) bool {
	if r.Type != "deb" && r.Type != "rpm" {
		return false
	}
	pu, err := packageurl.FromString(r.Purl)
	if err != nil {
		return false
	}
	role, _ := osv.KernelPackage(r.Type, pu.Name, r.Version)
	return role != osv.NotKernel
}

// mergeKernelFindings turns the findings of one kernel version's packages
// (by inventory row) into one finding per issue on the reporting package.
// Nothing is dropped: severities, sources and ranges are combined, a free
// fix wins over a paid-channel one, and the highest fixed version is kept.
func mergeKernelFindings(found map[int64][]store.FindingInput, kernels map[int64]*kernelSlot) []store.FindingInput {
	var slot *kernelSlot
	ids := make([]int64, 0, len(found))
	for id := range found {
		ids = append(ids, id)
		if slot == nil {
			slot = kernels[id]
		}
	}
	if slot == nil {
		return nil
	}
	rep := slot.rep
	sort.Slice(ids, func(i, j int) bool {
		if (ids[i] == rep.InventoryID) != (ids[j] == rep.InventoryID) {
			return ids[i] == rep.InventoryID
		}
		return ids[i] < ids[j]
	})
	cmp := version.For(version.ForPurlType(rep.Type))
	byKey := map[string]*store.FindingInput{}
	var order []string
	for _, id := range ids {
		for _, f := range found[id] {
			cur := byKey[f.Key]
			if cur == nil {
				c := f
				byKey[f.Key] = &c
				order = append(order, f.Key)
				continue
			}
			mergeFinding(cur, f, cmp)
		}
	}
	notRunning := false
	if pu, err := packageurl.FromString(rep.Purl); err == nil {
		notRunning = osv.KernelNotRunning(rep.Type, pu.Name, rep.Version, rep.RunningKernel)
	}
	out := make([]store.FindingInput, 0, len(order))
	for _, k := range order {
		f := byKey[k]
		f.InventoryID, f.AssetID, f.ComponentID = rep.InventoryID, rep.AssetID, rep.ComponentID
		f.Evidence["kernel_release"] = slot.release
		f.Evidence["kernel_packages"] = slot.members
		if notRunning {
			f.Evidence["not_running_kernel"] = true
			f.Evidence["running_kernel"] = rep.RunningKernel
		} else {
			delete(f.Evidence, "not_running_kernel")
			delete(f.Evidence, "running_kernel")
		}
		out = append(out, *f)
	}
	return out
}

// mergeFinding folds f (same issue, another package of the same kernel
// version) into cur.
func mergeFinding(cur *store.FindingInput, f store.FindingInput, cmp version.Comparator) {
	curPaid, fPaid := cur.Evidence["requires_subscription"] != nil, f.Evidence["requires_subscription"] != nil
	switch {
	case curPaid && !fPaid:
		// A free fix exists for this kernel version.
		cur.FixedVersion = f.FixedVersion
		delete(cur.Evidence, "requires_subscription")
		delete(cur.Evidence, "requires_ubuntu_pro")
	case curPaid == fPaid && f.FixedVersion != "":
		if cur.FixedVersion == "" {
			cur.FixedVersion = f.FixedVersion
		} else if c, err := cmp(f.FixedVersion, cur.FixedVersion); err == nil && c > 0 {
			cur.FixedVersion = f.FixedVersion
		}
	}
	if osv.LevelRank(f.Severity) > osv.LevelRank(cur.Severity) {
		cur.Severity, cur.Score = f.Severity, f.Score
	}
	if strings.HasPrefix(cur.Title, cur.Key+" in ") && !strings.HasPrefix(f.Title, f.Key+" in ") {
		// Prefer an advisory summary to the generated title.
		cur.Title = f.Title
	}
	for _, s := range f.Sources {
		cur.Sources = appendUnique(cur.Sources, s)
	}
	sort.Strings(cur.Sources)
	for _, field := range []string{"matched_ranges", "osv_ecosystems"} {
		a, _ := cur.Evidence[field].([]string)
		b, _ := f.Evidence[field].([]string)
		for _, v := range b {
			a = appendUnique(a, v)
		}
		cur.Evidence[field] = a
	}
	if x, _ := f.Evidence["known_exploited"].(bool); x {
		cur.Evidence["known_exploited"] = true
	}
	if l, _ := f.Evidence["advisory_level"].(string); osv.LevelRank(l) > osv.LevelRank(fmt.Sprint(cur.Evidence["advisory_level"])) {
		cur.Evidence["advisory_level"] = l
	}
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
