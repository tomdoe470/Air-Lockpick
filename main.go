package main

import (
	"fmt"
	"os"

	"github.com/auditteam/wifiaudit/cmd"
)

func main() {
	if os.Geteuid() != 0 {
		fmt.Fprintf(os.Stderr, "\033[31m[!] wifiaudit must be run as root\033[0m\n")
		os.Exit(1)
	}
	cmd.Execute()
}
