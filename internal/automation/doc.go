// Package automation runs reviewed workflows (runbooks) on saved SSH
// hosts: the runbook library, the review of a run with its frozen
// inventory, the start behind a typed confirmation and an account
// step-up, the run itself over internal/ssh/remotecmd, the run history
// with its export as JSON and CSV, and the run interface the schedules
// build on.
//
// A step's command is the exec request, as the Python release sent it
// (remotecmd.Shell): the login shell of the target account interprets
// it, with sudo it runs under "sudo -n -- sh -c". Passwords come only from the
// saved passwords of internal/vault, bound to the target the user
// reviewed; host keys must already be trusted, nothing is accepted on
// first use.
package automation
