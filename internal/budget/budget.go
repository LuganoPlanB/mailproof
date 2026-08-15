// Package budget defines the single effective resource policy for collectors and workers.
package budget

import (
	"errors"
	"fmt"
	"time"
)

type Limits struct {
	MessageBytes, MIMEParts, MIMEDepth, DecodedPartBytes, ArchiveDepth, ExtractedFiles, ExtractionBytes               int64
	CompressionRatio, URLs, Redirects, FetchBytes, ToolStdoutBytes, ToolStderrBytes, AnalysisAttempts, ReportAttempts int64
	ConnectTimeout, AnalyzerTimeout, WorkerLease, LeaseRenewal                                                        time.Duration
}

func Default() Limits {
	return Limits{50 << 20, 1000, 30, 10 << 20, 5, 1000, 250 << 20, 100, 100, 5, 5 << 20, 1 << 20, 256 << 10, 3, 3, 10 * time.Second, 60 * time.Second, 5 * time.Minute, time.Minute}
}
func (l Limits) Validate() error {
	values := []int64{l.MessageBytes, l.MIMEParts, l.MIMEDepth, l.DecodedPartBytes, l.ArchiveDepth, l.ExtractedFiles, l.ExtractionBytes, l.CompressionRatio, l.URLs, l.Redirects, l.FetchBytes, l.ToolStdoutBytes, l.ToolStderrBytes, l.AnalysisAttempts, l.ReportAttempts}
	for _, value := range values {
		if value <= 0 {
			return errors.New("all budget limits must be positive")
		}
	}
	if l.DecodedPartBytes > l.MessageBytes || l.ExtractionBytes < l.DecodedPartBytes {
		return fmt.Errorf("inconsistent budget hierarchy")
	}
	if l.ConnectTimeout <= 0 || l.AnalyzerTimeout <= 0 || l.WorkerLease <= 0 || l.LeaseRenewal <= 0 || l.LeaseRenewal >= l.WorkerLease {
		return errors.New("budget durations must be positive and renew before lease expiry")
	}
	return nil
}
