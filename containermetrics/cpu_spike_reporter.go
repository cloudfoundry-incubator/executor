package containermetrics

import (
	"time"

	loggingclient "code.cloudfoundry.org/diego-logging-client"
	"code.cloudfoundry.org/executor"
	"code.cloudfoundry.org/lager"
)

type spikeInfo struct {
	start time.Time
	end   time.Time
}

type CPUSpikeReporter struct {
	spikeInfos   map[string]*spikeInfo
	metronClient loggingclient.IngressClient
}

func NewCPUSpikeReporter(metronClient loggingclient.IngressClient) *CPUSpikeReporter {
	return &CPUSpikeReporter{
		spikeInfos:   make(map[string]*spikeInfo),
		metronClient: metronClient,
	}
}

func (reporter *CPUSpikeReporter) Report(logger lager.Logger, containers []executor.Container, metrics map[string]executor.Metrics, timeStamp time.Time) error {
	for _, container := range containers {
		guid := container.Guid
		metric, ok := metrics[guid]
		if !ok {
			continue
		}

		previousSpikeInfo := reporter.spikeInfos[guid]
		currentSpikeInfo := &spikeInfo{}

		if previousSpikeInfo != nil {
			currentSpikeInfo.start = previousSpikeInfo.start
			currentSpikeInfo.end = previousSpikeInfo.end
		}

		if spikeStarted(metric, previousSpikeInfo) {
			currentSpikeInfo.start = timeStamp
			currentSpikeInfo.end = time.Time{}
		}

		if spikeEnded(metric, previousSpikeInfo) {
			currentSpikeInfo.end = timeStamp
		}

		reporter.spikeInfos[guid] = currentSpikeInfo

		if !currentSpikeInfo.start.IsZero() {
			err := reporter.metronClient.SendSpikeMetrics(loggingclient.SpikeMetric{
				Start: currentSpikeInfo.start,
				End:   currentSpikeInfo.end,
				Tags:  metric.MetricsConfig.Tags,
			})
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func spikeStarted(metric executor.Metrics, previousSpikeInfo *spikeInfo) bool {
	currentlySpiking := uint64(metric.TimeSpentInCPU.Nanoseconds()) > metric.AbsoluteCPUEntitlementInNanoseconds
	previouslySpiking := previousSpikeInfo != nil && !previousSpikeInfo.start.IsZero() && previousSpikeInfo.end.IsZero()
	return currentlySpiking && !previouslySpiking
}

func spikeEnded(metric executor.Metrics, previousSpikeInfo *spikeInfo) bool {
	currentlySpiking := uint64(metric.TimeSpentInCPU.Nanoseconds()) > metric.AbsoluteCPUEntitlementInNanoseconds
	previouslySpiking := previousSpikeInfo != nil && !previousSpikeInfo.start.IsZero() && previousSpikeInfo.end.IsZero()
	return !currentlySpiking && previouslySpiking
}
