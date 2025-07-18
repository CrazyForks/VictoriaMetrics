package logstorage

import (
	"github.com/VictoriaMetrics/VictoriaLogs/lib/prefixfilter"
)

// filterNot negates the filter.
//
// It is expressed as `NOT f` or `!f` in LogsQL.
type filterNot struct {
	f filter
}

func (fn *filterNot) String() string {
	s := fn.f.String()
	switch fn.f.(type) {
	case *filterAnd, *filterOr:
		return "!(" + s + ")"
	default:
		return "!" + s
	}
}

func (fn *filterNot) updateNeededFields(pf *prefixfilter.Filter) {
	fn.f.updateNeededFields(pf)
}

func (fn *filterNot) applyToBlockResult(br *blockResult, bm *bitmap) {
	// Minimize the number of rows to check by the filter by applying it
	// only to the rows, which match the bm, e.g. they may change the bm result.
	bmTmp := getBitmap(bm.bitsLen)
	bmTmp.copyFrom(bm)
	fn.f.applyToBlockResult(br, bmTmp)
	bm.andNot(bmTmp)
	putBitmap(bmTmp)
}

func (fn *filterNot) applyToBlockSearch(bs *blockSearch, bm *bitmap) {
	// Minimize the number of rows to check by the filter by applying it
	// only to the rows, which match the bm, e.g. they may change the bm result.
	bmTmp := getBitmap(bm.bitsLen)
	bmTmp.copyFrom(bm)
	fn.f.applyToBlockSearch(bs, bmTmp)
	bm.andNot(bmTmp)
	putBitmap(bmTmp)
}
