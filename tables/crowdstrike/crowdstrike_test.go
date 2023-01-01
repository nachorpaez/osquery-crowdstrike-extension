package crowdstrike

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"testing"

	"github.com/osquery/osquery-go/plugin/table"
)

func fakeExecCommand(command string, args ...string) *exec.Cmd {
	cs := []string{"-test.run=TestHelperProcess", "--", command}
	cs = append(cs, args...)
	cmd := exec.Command(os.Args[0], cs...)
	cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1"}
	return cmd
}

func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	// Print out the test value to stdout
	falconctlResult, err := os.ReadFile("test_stats.plist")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(os.Stdout, string(falconctlResult))
	os.Exit(0)
}

func TestFalconGenerate(t *testing.T) {
	execCommand = fakeExecCommand
	defer func() { execCommand = exec.Command }()
	rows, err := FalconGenerate(context.Background(), table.QueryContext{})
	if err != nil {
		t.Fatal(err)
	}
	expectedRows := []map[string]string{
		{
			"version":            "6.11.13304.0",
			"agent_id":           "60ADE91E-9289-49D3-A333-AADA7257655E",
			"customer_id":        "D417DDAD-0751-4617-BDE4-496A74DACF82",
			"sensor_operational": "true",
			"es_notify":          "0",
			"es_exec":            "0",
			"es_auth":            "0",
			"install_guard":      "Enabled",
		},
	}
	if !reflect.DeepEqual(rows, expectedRows) {
		t.Fatalf("rows mismatch: %+v vs. %+v", rows, expectedRows)
	}
}
