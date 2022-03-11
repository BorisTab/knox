package client

import (
	"fmt"

	"github.com/pavelzhurov/knox"
)

var cmdReactivate = &Command{
	Run:       runReactivate,
	UsageLine: "reactivate <key_identifier> <key_version>",
	Short:     "Reactivates an inactive key version",
	Long: `
Reactivate makes an inactive key version active.

Active keys are not used by default, but can still be used if the primary key fails.
Inactive keys should not be used for any purpose.

This command requires write access to the key.

For more about knox, see https://github.com/pavelzhurov/knox.

See also: knox deactivate, knox promote
	`,
}

func runReactivate(cmd *Command, args []string) {
	if len(args) != 2 {
		fatalf("reactivate takes exactly two argument. See 'knox help reactivate'")
	}
	keyID := args[0]
	versionID := args[1]

	err := cli.UpdateVersion(keyID, versionID, knox.Active)
	if err != nil {
		fatalf("Error reactivating version: %s", err.Error())
	}
	fmt.Printf("Reactivated %s successfully.\n", versionID)
}
