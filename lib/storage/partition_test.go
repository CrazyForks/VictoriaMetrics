package storage

import (
	"math/rand"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/VictoriaMetrics/VictoriaMetrics/lib/fs"
)

func TestPartitionGetMaxOutBytes(t *testing.T) {
	n := getMaxOutBytes(".", 1)
	if n < 1e3 {
		t.Fatalf("too small free space remained in the current directory: %d", n)
	}
}

func TestAppendPartsToMerge(t *testing.T) {
	testAppendPartsToMerge(t, 2, []uint64{}, nil)
	testAppendPartsToMerge(t, 2, []uint64{123}, nil)
	testAppendPartsToMerge(t, 2, []uint64{4, 2}, nil)
	testAppendPartsToMerge(t, 2, []uint64{128, 64, 32, 16, 8, 4, 2, 1}, nil)
	testAppendPartsToMerge(t, 4, []uint64{128, 64, 32, 10, 9, 7, 3, 1}, []uint64{3, 7, 9, 10})
	testAppendPartsToMerge(t, 2, []uint64{128, 64, 32, 16, 8, 4, 2, 2}, []uint64{2, 2})
	testAppendPartsToMerge(t, 4, []uint64{128, 64, 32, 16, 8, 4, 2, 2}, []uint64{2, 2, 4, 8})
	testAppendPartsToMerge(t, 2, []uint64{1, 1}, []uint64{1, 1})
	testAppendPartsToMerge(t, 2, []uint64{2, 2, 2}, []uint64{2, 2})
	testAppendPartsToMerge(t, 2, []uint64{4, 2, 4}, []uint64{4, 4})
	testAppendPartsToMerge(t, 2, []uint64{1, 3, 7, 2}, nil)
	testAppendPartsToMerge(t, 3, []uint64{1, 3, 7, 2}, []uint64{1, 2, 3})
	testAppendPartsToMerge(t, 4, []uint64{1, 3, 7, 2}, []uint64{1, 2, 3})
	testAppendPartsToMerge(t, 5, []uint64{1, 3, 7, 2}, nil)
	testAppendPartsToMerge(t, 4, []uint64{1e6, 3e6, 7e6, 2e6}, []uint64{1e6, 2e6, 3e6})
	testAppendPartsToMerge(t, 4, []uint64{2, 3, 7, 2}, []uint64{2, 2, 3})
	testAppendPartsToMerge(t, 5, []uint64{2, 3, 7, 2}, nil)
	testAppendPartsToMerge(t, 3, []uint64{11, 1, 10, 100, 10}, []uint64{10, 10, 11})
}

func TestAppendPartsToMergeManyParts(t *testing.T) {
	// Verify that big number of parts are merged into minimal number of parts
	// using minimum merges.
	var sizes []uint64
	maxOutSize := uint64(0)
	r := rand.New(rand.NewSource(1))
	for i := 0; i < 1024; i++ {
		n := uint64(uint32(r.NormFloat64() * 1e9))
		n++
		maxOutSize += n
		sizes = append(sizes, n)
	}
	pws := newTestPartWrappersForSizes(sizes)

	iterationsCount := 0
	sizeMergedTotal := uint64(0)
	for {
		pms := appendPartsToMerge(nil, pws, defaultPartsToMerge, maxOutSize)
		if len(pms) == 0 {
			break
		}
		m := make(map[*partWrapper]bool)
		for _, pw := range pms {
			m[pw] = true
		}
		var pwsNew []*partWrapper
		size := uint64(0)
		for _, pw := range pws {
			if m[pw] {
				size += pw.p.size
			} else {
				pwsNew = append(pwsNew, pw)
			}
		}
		pw := &partWrapper{
			p: &part{
				size: size,
			},
		}
		sizeMergedTotal += size
		pwsNew = append(pwsNew, pw)
		pws = pwsNew
		iterationsCount++
	}
	sizes = newTestSizesFromPartWrappers(pws)
	sizeTotal := uint64(0)
	for _, size := range sizes {
		sizeTotal += uint64(size)
	}
	overhead := float64(sizeMergedTotal) / float64(sizeTotal)
	if overhead > 2.1 {
		t.Fatalf("too big overhead; sizes=%d, iterationsCount=%d, sizeTotal=%d, sizeMergedTotal=%d, overhead=%f",
			sizes, iterationsCount, sizeTotal, sizeMergedTotal, overhead)
	}
	if len(sizes) > 18 {
		t.Fatalf("too many sizes %d; sizes=%d, iterationsCount=%d, sizeTotal=%d, sizeMergedTotal=%d, overhead=%f",
			len(sizes), sizes, iterationsCount, sizeTotal, sizeMergedTotal, overhead)
	}
}

func testAppendPartsToMerge(t *testing.T, maxPartsToMerge int, initialSizes, expectedSizes []uint64) {
	t.Helper()

	pws := newTestPartWrappersForSizes(initialSizes)

	// Verify appending to nil.
	pms := appendPartsToMerge(nil, pws, maxPartsToMerge, 1e9)
	sizes := newTestSizesFromPartWrappers(pms)
	if !reflect.DeepEqual(sizes, expectedSizes) {
		t.Fatalf("unexpected size for maxPartsToMerge=%d, initialSizes=%d; got\n%d; want\n%d",
			maxPartsToMerge, initialSizes, sizes, expectedSizes)
	}

	// Verify appending to prefix
	prefix := []*partWrapper{
		{
			p: &part{
				size: 1234,
			},
		},
		{},
		{},
	}
	pms = appendPartsToMerge(prefix, pws, maxPartsToMerge, 1e9)
	if !reflect.DeepEqual(pms[:len(prefix)], prefix) {
		t.Fatalf("unexpected prefix for maxPartsToMerge=%d, initialSizes=%d; got\n%+v; want\n%+v",
			maxPartsToMerge, initialSizes, pms[:len(prefix)], prefix)
	}

	sizes = newTestSizesFromPartWrappers(pms[len(prefix):])
	if !reflect.DeepEqual(sizes, expectedSizes) {
		t.Fatalf("unexpected prefixed sizes for maxPartsToMerge=%d, initialSizes=%d; got\n%d; want\n%d",
			maxPartsToMerge, initialSizes, sizes, expectedSizes)
	}
}

func newTestSizesFromPartWrappers(pws []*partWrapper) []uint64 {
	var sizes []uint64
	for _, pw := range pws {
		sizes = append(sizes, pw.p.size)
	}
	return sizes
}

func newTestPartWrappersForSizes(sizes []uint64) []*partWrapper {
	var pws []*partWrapper
	for _, size := range sizes {
		pw := &partWrapper{
			p: &part{
				size: size,
			},
		}
		pws = append(pws, pw)
	}
	return pws
}

func TestMergeInMemoryPartsEmptyResult(t *testing.T) {
	defer testRemoveAll(t)

	s := newTestStorage()
	s.retentionMsecs = 1000
	defer stopTestStorage(s)

	timestamp := int64(0)
	pt := testCreatePartition(t, timestamp, s)
	defer pt.MustClose()

	var pws []*partWrapper
	const (
		inMemoryPartsCount = 5
		rowsCount          = 10
	)

	for range inMemoryPartsCount {
		rows := make([]rawRow, rowsCount)
		for i := range rowsCount {
			rows[i].TSID = TSID{
				MetricID: uint64(i),
			}
			rows[i].Value = float64(i)
			rows[i].Timestamp = timestamp + int64(i)
			rows[i].PrecisionBits = 64
		}

		pws = append(pws, &partWrapper{
			mp: newTestInmemoryPart(rows),
			p:  &part{},
		})
	}

	pwsNew := pt.mustMergeInmemoryParts(pws)
	if len(pwsNew) != 0 {
		t.Fatalf("unexpected non-empty pwsNew: %d", len(pwsNew))
	}
}

func testCreatePartition(t *testing.T, timestamp int64, s *Storage) *partition {
	t.Helper()
	small := filepath.Join(t.Name(), smallDirname)
	big := filepath.Join(t.Name(), bigDirname)
	return mustCreatePartition(timestamp, small, big, s)
}

func TestMustCreatePartition(t *testing.T) {
	defer testRemoveAll(t)

	ts := time.Date(2025, 3, 23, 14, 07, 56, 999_999_999, time.UTC).UnixMilli()
	smallPath := filepath.Join(t.Name(), "small")
	if fs.IsPathExist(smallPath) {
		t.Errorf("small partition directory must not exist: %s", smallPath)
	}
	bigPath := filepath.Join(t.Name(), "big")
	if fs.IsPathExist(bigPath) {
		t.Errorf("big partition directory must not exist: %s", bigPath)
	}
	s := &Storage{}

	got := mustCreatePartition(ts, smallPath, bigPath, s)
	defer got.MustClose()

	wantSmallPartsPath := filepath.Join(smallPath, "2025_03")
	if got.smallPartsPath != wantSmallPartsPath {
		t.Errorf("unexpected small parts path: got %s, want %s", got.smallPartsPath, wantSmallPartsPath)
	}
	if !fs.IsPathExist(wantSmallPartsPath) {
		t.Errorf("small parts directory hasn't been created: %s", wantSmallPartsPath)
	}
	wantBigPartsPath := filepath.Join(bigPath, "2025_03")
	if got.bigPartsPath != wantBigPartsPath {
		t.Errorf("unexpected big parts path: got %s, want %s", got.bigPartsPath, wantBigPartsPath)
	}
	if !fs.IsPathExist(wantBigPartsPath) {
		t.Errorf("big parts directory hasn't been created: %s", wantBigPartsPath)
	}
	wantStorage := s
	if got.s != wantStorage {
		t.Errorf("unexpected storage: got %v, want %v", got.s, wantStorage)
	}
	wantName := "2025_03"
	if got.name != wantName {
		t.Errorf("unexpected name: got %s, want %s", got.name, wantName)
	}
	wantTR := TimeRange{
		MinTimestamp: time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC).UnixMilli(),
		MaxTimestamp: time.Date(2025, 3, 31, 23, 59, 59, 999_000_000, time.UTC).UnixMilli(),
	}
	if got.tr != wantTR {
		t.Errorf("unexpected time range: got %v, want %v", &got.tr, &wantTR)
	}

}

func TestMustOpenPartition(t *testing.T) {
	defer testRemoveAll(t)

	smallPartsPath := filepath.Join(t.Name(), "small", "2025_03")
	bigPartsPath := filepath.Join(t.Name(), "big", "2025_03")

	s := &Storage{}

	got := mustOpenPartition(smallPartsPath, bigPartsPath, s)
	defer got.MustClose()

	if got.smallPartsPath != smallPartsPath {
		t.Errorf("unexpected small parts path: got %s, want %s", got.smallPartsPath, smallPartsPath)
	}
	if !fs.IsPathExist(smallPartsPath) {
		t.Errorf("small parts directory hasn't been created: %s", smallPartsPath)
	}
	if got.bigPartsPath != bigPartsPath {
		t.Errorf("unexpected big parts path: got %s, want %s", got.bigPartsPath, bigPartsPath)
	}
	if !fs.IsPathExist(bigPartsPath) {
		t.Errorf("big parts directory hasn't been created: %s", bigPartsPath)
	}
	if got.s != s {
		t.Errorf("unexpected storage: got %v, want %v", got.s, s)
	}
	wantName := "2025_03"
	if got.name != wantName {
		t.Errorf("unexpected name: got %s, want %s", got.name, wantName)
	}
	wantTR := TimeRange{
		MinTimestamp: time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC).UnixMilli(),
		MaxTimestamp: time.Date(2025, 3, 31, 23, 59, 59, 999_000_000, time.UTC).UnixMilli(),
	}
	if got.tr != wantTR {
		t.Errorf("unexpected time range: got %v, want %v", &got.tr, &wantTR)
	}

}

func TestMustOpenPartition_invalidPartitionName(t *testing.T) {
	defer testRemoveAll(t)

	smallPartsPath := filepath.Join(t.Name(), "small", "2025_03_invalid")
	bigPartsPath := filepath.Join(t.Name(), "big", "2025_03_invalid")

	defer func() {
		if err := recover(); err == nil {
			t.Fatalf("expected panic on invalid partition name in smallPartsPath but it did not happen: %v", smallPartsPath)
		}
	}()

	s := &Storage{}
	_ = mustOpenPartition(smallPartsPath, bigPartsPath, s)

}

func TestMustOpenPartition_smallAndBigPartsPathsAreNotTheSame(t *testing.T) {
	defer testRemoveAll(t)

	smallPartsPath := filepath.Join(t.Name(), "small", "2025_03")
	bigPartsPath := filepath.Join(t.Name(), "big", "2025_04")
	defer func() {
		if err := recover(); err == nil {
			t.Fatalf("expected panic on different partition name in smallPartsPath=%v and bigPartsPath=%v but it did not happen", smallPartsPath, bigPartsPath)
		}
	}()

	s := &Storage{}
	_ = mustOpenPartition(smallPartsPath, bigPartsPath, s)

}
