package client

import (
	"fmt"
)

var cmdDelete = &Command{
	Run:       runDelete,
	UsageLine: "delete <key_identifier>",
	Short:     "deletes an existing key",
	Long: `
This will delete your key and all data from the knox server. This operation is dangerous and requires admin permissions

For more about knox, see https://github.com/pavelzhurov/knox.

See also: knox create
    `,
}

func runDelete(cmd *Command, args []string) {
	if len(args) != 1 {
		fatalf("create takes exactly one argument. See 'knox help delete'")
	}

	err := cli.DeleteKey(args[0])
	if err != nil {
		fatalf("Error deleting key: %s", err.Error())
	}
	fmt.Printf("Successfully deleted key\n")
}
