package promdb

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"time"

	"github.com/oklog/ulid"
	"github.com/prometheus/prometheus/model/labels"
	promstorage "github.com/prometheus/prometheus/storage"
	"github.com/prometheus/prometheus/tsdb"
	"github.com/prometheus/prometheus/tsdb/chunkenc"

	"github.com/VictoriaMetrics/VictoriaMetrics/app/vmselect/searchutil"
	"github.com/VictoriaMetrics/VictoriaMetrics/lib/logger"
	"github.com/VictoriaMetrics/VictoriaMetrics/lib/storage"
)

var prometheusDataPath = flag.String("prometheusDataPath", "", "Optional path to readonly historical Prometheus data")

var prometheusRetentionMsecs int64

// Init must be called after flag.Parse and before using the package.
//
// See also MustClose.
func Init(retentionMsecs int64) {
	if promDB != nil {
		logger.Fatalf("BUG: promdb.Init is called multiple times without promdb.MustClose call")
	}
	prometheusRetentionMsecs = retentionMsecs
	if *prometheusDataPath == "" {
		return
	}
	l := slog.New(slog.Default().Handler())
	opts := tsdb.DefaultOptions()
	opts.RetentionDuration = retentionMsecs

	// Set max block duration to 10% of retention period or 31 days
	// according to https://prometheus.io/docs/prometheus/latest/storage/#compaction
	maxBlockDuration := int64((31 * 24 * time.Hour) / time.Millisecond)
	if maxBlockDuration > retentionMsecs/10 {
		maxBlockDuration = retentionMsecs / 10
	}
	if maxBlockDuration < opts.MinBlockDuration {
		maxBlockDuration = opts.MinBlockDuration
	}
	opts.MaxBlockDuration = maxBlockDuration

	// Custom delete function is needed, because Prometheus by default doesn't delete
	// blocks outside the retention if no new blocks are created with samples with the current timestamps.
	// See https://github.com/prometheus/prometheus/blob/997bb7134fcfd7279f250e183e78681e48a56aff/tsdb/db.go#L1116
	opts.BlocksToDelete = func(blocks []*tsdb.Block) map[ulid.ULID]struct{} {
		m := make(map[ulid.ULID]struct{})
		minRetentionTime := time.Now().Unix()*1000 - retentionMsecs
		for _, block := range blocks {
			meta := block.Meta()
			// delete block marked for deletion by compaction code.
			if meta.Compaction.Deletable {
				m[meta.ULID] = struct{}{}
				continue
			}
			if block.MaxTime() < minRetentionTime {
				m[meta.ULID] = struct{}{}
			}
		}
		return m
	}
	pdb, err := tsdb.Open(*prometheusDataPath, l, nil, opts, nil)
	if err != nil {
		logger.Panicf("FATAL: cannot open Prometheus data at -prometheusDataPath=%q: %s", *prometheusDataPath, err)
	}
	promDB = pdb
	logger.Infof("successfully opened historical Prometheus data at -prometheusDataPath=%q with retentionMsecs=%d", *prometheusDataPath, retentionMsecs)
}

// MustClose must be called on graceful shutdown.
//
// Package functionality cannot be used after this call.
func MustClose() {
	if *prometheusDataPath == "" {
		return
	}
	if promDB == nil {
		logger.Panicf("BUG: promdb.MustClose is called without promdb.Init call")
	}
	if err := promDB.Close(); err != nil {
		logger.Panicf("FATAL: cannot close promDB: %s", err)
	}
	promDB = nil
	logger.Infof("successfully closed historical Prometheus data at -prometheusDataPath=%q", *prometheusDataPath)
}

var promDB *tsdb.DB

// GetLabelNamesOnTimeRange returns label names.
func GetLabelNamesOnTimeRange(tr storage.TimeRange, deadline searchutil.Deadline) ([]string, error) {
	if *prometheusDataPath == "" {
		return nil, nil
	}
	d := time.Unix(int64(deadline.Deadline()), 0)
	ctx, cancel := context.WithDeadline(context.Background(), d)
	defer cancel()
	q, err := promDB.Querier(tr.MinTimestamp, tr.MaxTimestamp)
	if err != nil {
		return nil, err
	}
	defer mustCloseQuerier(q)

	names, _, err := q.LabelNames(ctx, nil)
	// Make full copy of names, since they cannot be used after q is closed.
	names = copyStringsWithMemory(names)
	return names, err
}

// GetLabelValuesOnTimeRange returns values for the given labelName on the given tr.
func GetLabelValuesOnTimeRange(labelName string, tr storage.TimeRange, deadline searchutil.Deadline) ([]string, error) {
	if *prometheusDataPath == "" {
		return nil, nil
	}
	d := time.Unix(int64(deadline.Deadline()), 0)
	ctx, cancel := context.WithDeadline(context.Background(), d)
	defer cancel()
	q, err := promDB.Querier(tr.MinTimestamp, tr.MaxTimestamp)
	if err != nil {
		return nil, err
	}
	defer mustCloseQuerier(q)

	values, _, err := q.LabelValues(ctx, labelName, nil)
	// Make full copy of values, since they cannot be used after q is closed.
	values = copyStringsWithMemory(values)
	return values, err
}

func copyStringsWithMemory(a []string) []string {
	result := make([]string, len(a))
	for i, s := range a {
		result[i] = string(append([]byte{}, s...))
	}
	return result
}

// SeriesVisitor is called by VisitSeries for each matching time series.
//
// The caller shouldn't hold references to metricName, values and timestamps after returning.
type SeriesVisitor func(metricName []byte, values []float64, timestamps []int64)

// VisitSeries calls f for each series found in the pdb.
func VisitSeries(sq *storage.SearchQuery, deadline searchutil.Deadline, f SeriesVisitor) error {
	if *prometheusDataPath == "" {
		return nil
	}
	d := time.Unix(int64(deadline.Deadline()), 0)
	ctx, cancel := context.WithDeadline(context.Background(), d)
	defer cancel()
	minTime, maxTime := getSearchTimeRange(sq)
	q, err := promDB.Querier(minTime, maxTime)
	if err != nil {
		return err
	}
	defer mustCloseQuerier(q)
	var seriesSet []promstorage.SeriesSet
	for _, tf := range sq.TagFilterss {
		ms, err := convertTagFiltersToMatchers(tf)
		if err != nil {
			return fmt.Errorf("cannot convert tag filters to matchers: %w", err)
		}
		s := q.Select(ctx, false, nil, ms...)
		seriesSet = append(seriesSet, s)
	}
	ss := promstorage.NewMergeSeriesSet(seriesSet, 0, promstorage.ChainedSeriesMerge)
	var (
		mn         storage.MetricName
		metricName []byte
		values     []float64
		timestamps []int64
	)
	var it chunkenc.Iterator
	for ss.Next() {
		s := ss.At()
		convertPromLabelsToMetricName(&mn, s.Labels())
		metricName = mn.SortAndMarshal(metricName[:0])
		values = values[:0]
		timestamps = timestamps[:0]
		it = s.Iterator(it)
		for {
			typ := it.Next()
			if typ == chunkenc.ValNone {
				break
			}
			if typ != chunkenc.ValFloat {
				// Skip unsupported values
				continue
			}
			ts, v := it.At()
			values = append(values, v)
			timestamps = append(timestamps, ts)
		}
		if err := it.Err(); err != nil {
			return fmt.Errorf("error when iterating Prometheus series: %w", err)
		}
		f(metricName, values, timestamps)
	}
	return ss.Err()
}

func getSearchTimeRange(sq *storage.SearchQuery) (int64, int64) {
	maxTime := sq.MaxTimestamp
	minTime := sq.MinTimestamp
	minRetentionTime := time.Now().Unix()*1000 - prometheusRetentionMsecs
	if maxTime < minRetentionTime {
		maxTime = minRetentionTime
	}
	if minTime < minRetentionTime {
		minTime = minRetentionTime
	}
	return minTime, maxTime
}

func convertPromLabelsToMetricName(dst *storage.MetricName, labels []labels.Label) {
	dst.Reset()
	for _, label := range labels {
		if label.Name == "__name__" {
			dst.MetricGroup = append(dst.MetricGroup[:0], label.Value...)
		} else {
			dst.AddTag(label.Name, label.Value)
		}
	}
}

func convertTagFiltersToMatchers(tfs []storage.TagFilter) ([]*labels.Matcher, error) {
	ms := make([]*labels.Matcher, 0, len(tfs))
	for _, tf := range tfs {
		var mt labels.MatchType
		if tf.IsNegative {
			if tf.IsRegexp {
				mt = labels.MatchNotRegexp
			} else {
				mt = labels.MatchNotEqual
			}
		} else {
			if tf.IsRegexp {
				mt = labels.MatchRegexp
			} else {
				mt = labels.MatchEqual
			}
		}
		key := string(tf.Key)
		if key == "" {
			key = "__name__"
		}
		value := string(tf.Value)
		m, err := labels.NewMatcher(mt, key, value)
		if err != nil {
			return nil, err
		}
		ms = append(ms, m)
	}
	return ms, nil
}

func mustCloseQuerier(q promstorage.Querier) {
	if err := q.Close(); err != nil {
		logger.Panicf("FATAL: cannot close querier: %s", err)
	}
}
