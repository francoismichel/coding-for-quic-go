package benchmark

import (
	"fmt"
	"os"

	"github.com/olekukonko/tablewriter"
	. "github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/config"
	"github.com/onsi/ginkgo/types"
)

const (
	transferRateLabel  = "transfer rate [MB/s]"
	testChromeToTCP    = "Chrome => TCP/HTTPS server"
	testChromeToQuicGo = "Chrome => quic-go server"
	testQuicGoToQuicGo = "quic-go client => server"
)

type measurementSeries map[string]*types.SpecMeasurement

type myReporter struct {
	Reporter

	results map[string]measurementSeries
}

var _ Reporter = &myReporter{}

func (r *myReporter) SpecSuiteWillBegin(config.GinkgoConfigType, *types.SuiteSummary) {}
func (r *myReporter) BeforeSuiteDidRun(*types.SetupSummary)                           {}
func (r *myReporter) SpecWillRun(*types.SpecSummary)                                  {}
func (r *myReporter) AfterSuiteDidRun(*types.SetupSummary)                            {}
func (r *myReporter) SpecSuiteDidEnd(*types.SuiteSummary)                             {}

func (r *myReporter) SpecDidComplete(specSummary *types.SpecSummary) {
	if !specSummary.IsMeasurement {
		return
	}
	test := specSummary.ComponentTexts[4]
	cond := specSummary.ComponentTexts[2]
	measurement, ok := specSummary.Measurements[transferRateLabel]
	if !ok {
		return
	}
	r.addResult(cond, test, measurement)
}

func (r *myReporter) addResult(cond, ver string, measurement *types.SpecMeasurement) {
	if r.results == nil {
		r.results = make(map[string]measurementSeries)
	}
	if _, ok := r.results[cond]; !ok {
		r.results[cond] = make(measurementSeries)
	}
	r.results[cond][ver] = measurement
}

func (r *myReporter) printResult() {
	table := tablewriter.NewWriter(os.Stdout)
	header := []string{"", testChromeToTCP, testChromeToQuicGo, testQuicGoToQuicGo}
	table.SetHeader(header)
	table.SetCaption(true, fmt.Sprintf("Based on %d samples of %d MB.\nAll values in MB/s.", samples, size))
	table.SetAutoFormatHeaders(false)
	colAlignments := []int{tablewriter.ALIGN_LEFT}
	for i := 1; i <= len(header); i++ {
		colAlignments = append(colAlignments, tablewriter.ALIGN_RIGHT)
	}
	table.SetColumnAlignment(colAlignments)

	for _, cond := range conditions {
		data := make([]string, len(header))
		data[0] = cond.Description

		for i := 1; i < len(header); i++ {
			measurement := r.results[cond.Description][header[i]]
			var out string
			if measurement == nil {
				out = "-"
			} else {
				if len(measurement.Results) <= 1 {
					out = fmt.Sprintf(" %.2f", measurement.Average)
				} else {
					out = fmt.Sprintf("%.2f ± %.2f", measurement.Average, measurement.StdDeviation)
				}
			}
			data[i] = out
		}
		table.Append(data)
	}
	table.Render()
}
