package crowdstrike

import (
	"context"
	"log"
	"os/exec"
	"strconv"

	"github.com/osquery/osquery-go/plugin/table"
	"github.com/pkg/errors"
	"howett.net/plist"
)

type Stats struct {
	EndpointSecurity EndpointSecurity `plist:"EndpointSecurity"`
	AgentInfo        AgentInfo        `plist:"agent_info"`
	DynamicSettings  DynamicSettings  `plist:"dynamic_settings"`
}

type AgentInfo struct {
	Version           string `plist:"version"`
	AgentID           string `plist:"agentID"`
	SensorOperational string `plist:"sensor_operational"`
	CustomerID        string `plist:"customerID"`
}

type EndpointSecurity struct {
	Notify           int `plist:"notify"`
	Exec             int `plist:"exec"`
	AuthLookupMisses int `plist:"authLookupMisses"`
	Setflags         int `plist:"setflags"`
	AuthLookupCount  int `plist:"authLookupCount"`
	AuthExecCount    int `plist:"authExecCount"`
	Signal           int `plist:"signal"`
	Timeouts         int `plist:"timeouts"`
	Auth             int `plist:"auth"`
}

type DynamicSettings struct {
	InstallGuard string `plist:"installGuard"`
}

func FalconColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("version"),
		table.TextColumn("agent_id"),
		table.TextColumn("customer_id"),
		table.TextColumn("sensor_operational"),
		table.TextColumn("install_guard"),
		table.IntegerColumn("es_notify"),
		table.IntegerColumn("es_exec"),
		table.IntegerColumn("es_auth"),
	}
}

var execCommand = exec.Command

const falconPath = "/Applications/Falcon.app/Contents/Resources/falconctl"

func GetFalconStats() (*Stats, error) {

	out, err := execCommand(falconPath, "stats --plist").Output()
	if err != nil {
		return nil, errors.Wrap(err, "calling falconctl stats --plist")
	}

	var cfg Stats
	_, err = plist.Unmarshal(out, &cfg)
	if err != nil {
		return nil, errors.Wrap(err, "parsing falconctl stats")
	}

	return &cfg, nil
}

// Per docs generator function has to return an array of map of strings
func FalconGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	stats, err := GetFalconStats()
	if err != nil {
		log.Println(err)
	}

	var values []map[string]string
	values = append(values, map[string]string{
		"version":            stats.AgentInfo.Version,
		"agent_id":           stats.AgentInfo.AgentID,
		"customer_id":        stats.AgentInfo.CustomerID,
		"sensor_operational": stats.AgentInfo.SensorOperational,
		"install_guard":      stats.DynamicSettings.InstallGuard,
		"es_notify":          strconv.Itoa(stats.EndpointSecurity.Exec),
		"es_exec":            strconv.Itoa(stats.EndpointSecurity.Notify),
		"es_auth":            strconv.Itoa(stats.EndpointSecurity.Auth),
	})

	return values, nil
}
