package client

import (
	"fmt"
)

var cmdUnregister = &Command{
	Run:       runUnregister,
	UsageLine: "unregister <key_identifier>",
	Short:     "unregister a key identifier from daemon",
	Long: `
Unregister stops cacheing and refreshing a specific key, deleting the associated files.

For more about knox, see https://github.com/pavelzhurov/knox.

See also: knox register, knox daemon
	`,
}

func runUnregister(cmd *Command, args []string) {
	if len(args) != 1 {
		fatalf("You must include a key ID to deregister. See 'knox help unregister'")
	}
	k := NewKeysFile(daemonFolder + daemonToRegister)
	err := k.Lock()
	if err != nil {
		fatalf("Error locking the register file: %s", err.Error())
	}
	defer k.Unlock()

	err = k.Remove([]string{args[0]})
	if err != nil {
		fatalf("Error removing the key: %s", err.Error())
	}
	fmt.Println("Unregistered key successfully")
}
