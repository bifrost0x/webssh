# Automation

WebSSH runs ordered SSH command steps on saved hosts, immediately or through explicitly approved cron schedules. It does not interpret Ansible playbooks, YAML/Jinja or declarative desired state. No agent is installed on targets.

## Enable

Enable **Automation** in **Administration → Integrations**. This persisted runtime setting requires no Compose change or restart. New installations default to disabled. Upgrades migrate an existing configured opt-in; afterwards the admin setting is authoritative. Use HTTPS. Password storage is a separate setting; see [saved passwords](credentials.md).

Save and verify SSH hosts first. Unknown, changed or revoked host keys are rejected, never automatically accepted. Direct SSH and hosts behind one saved jump host are supported with usable stored keys or assigned passwords. Each hop needs its own verified host key and credential: a password-based jump host needs its own saved password. The jump host and a target it reaches by address follow the SSH network policy; a target name that only the jump host can resolve must be on `PROXY_JUMP_REMOTE_DNS_ALLOWLIST` while internal SSH is blocked, exactly as for interactive connections. Changing the jump host invalidates reviewed runs and approved schedules. Gateways, Tailscale SSH and interactive prompts remain unsupported by this execution engine.

## Run now

1. Open **Automation → Workflows** in the main application. The searchable list shows saved workflows with their steps and **Execute now**, **Edit** and **Delete** actions. Choose **New** or **Edit** to open the separate **Editor** tab. Switching back to Workflows preserves the editor draft; deleting requires confirmation of the named workflow.
2. Add named steps. Select a step in the ordered list to edit its command, timeout and sudo settings beside it. Narrow screens stack the list and command editor. Steps run in independent shells: use a complete command such as `cd /path && command`. Copies from the command library are independent and require parameter review.
3. Continue to **Choose targets** and select hosts or groups. Filtering preserves hidden selections. Review the actual target count. The numbered stages stay directly accessible, and Back preserves your draft. The active stage is centered; Schedule is optional when running immediately.
4. **Save & review run** freezes exact commands, destinations and credential state for five minutes. Confirm the count and complete account reauthentication, including configured MFA.
5. **Runs** shows actual states, exit codes and durations. Stop remains available. Changing tabs preserves the terminal workspace.

Sudo uses `sudo -n -- sh -c ...` and requires remote noninteractive permission. No separate sudo password is stored. Stop-on-error and timeout controls remain enforced.

Commands run without interactive input. Package upgrades that ask for confirmation can therefore abort even when SSH and authentication succeeded. Review the package manager's unattended options explicitly; WebSSH does not add confirmation flags or answer prompts. The editor warns about common apt upgrade confirmation requirements, short package-upgrade timeouts and a duplicate `sudo` prefix when the sudo option is already enabled. Recognized apt confirmation-abort output is explained in the run details while preserving the original output and exit status. These hints are not a complete command validator. Automation executes SSH commands; it does not provide Ansible modules or idempotency guarantees.

Saved workflows provide **Execute now**. Choose destinations before reviewing: a workflow defines commands, while schedules retain their explicitly approved destinations. Nothing executes until the existing review and account-verification steps are complete.

## Scheduled execution

Choose **Schedule**, then select hourly, daily, weekdays, weekly or monthly. Set the time or day and the IANA timezone. The summary explains the selected cadence; **Review schedule** shows the next execution times calculated by the server. Monthly dates that do not occur in a month are skipped. Advanced schedules remain available through **Custom cron**; existing custom expressions are preserved when reopened. For example, `0 3 * * *` in `Europe/Berlin` means 03:00 daily in that timezone. Review exact commands and hosts and explicitly authorize unattended execution with account reauthentication and host-count confirmation.

A schedule is a durable, scoped authorization. Assigned passwords work without an open browser or temporary unlock. Normal logout does not revoke schedules, and locking saved passwords stops only runs started from the browser; a scheduled run already in progress finishes. Newly added group members are not silently included. Changes to the workflow, target, relevant keys/passwords, account security generation or feature policy require fresh approval. Account lock/deletion and restored session epochs invalidate grants.

- Pause stops future dispatch and further active steps. Delete removes the schedule, preserving run history.
- Missed occurrences during downtime are not replayed. There is no backlog or automatic retry.
- Overlapping occurrences are skipped while a previous claim remains active.
- Missing spring-forward local times are skipped; repeated autumn times fire only at their first occurrence.
- Crashes and ambiguous dispatches are not retried automatically. Unknown outcomes require inspection and explicit reapproval.
- Restored backups do not silently resume old unattended grants. Native backups exclude saved remote passwords, legacy password vaults and SSH keys; normal restore also ignores them in older archives and removes existing copies. Reimport keys, recreate passwords and reassign credentials, then review and explicitly re-enable schedules.

**Execute now** on a schedule reviews its stored commands and destinations for a separate immediate run, including when paused. It does not change the next scheduled time or enable a paused schedule. It uses fresh interactive authorization and current credentials, rather than reusing the unattended grant. Editing or deleting the source schedule invalidates a pending immediate-run review.

Disabling Automation preserves definitions, blocks starts and interrupts further work. Schedules remain accessible for pausing/removal while disabled.

## Results and boundaries

Expand a step in **Runs** to see its exit code, duration, execution reason and captured standard/error output. New immediate and scheduled runs retain bounded output; older records explicitly indicate that output was not recorded. Output becomes available when the step ends. A confirmed zero exit status means the command reported success, not that WebSSH independently verified the intended change.

At most 8 KiB of UTF-8 output per step and 64 KiB per run are retained. Truncation is marked; the history keeps at most 50 runs within its existing storage limit, so older entries may expire earlier. **Runs** lets the owner delete a single finished run or all finished runs; queued and running work cannot be deleted. Deleting removes only the stored result and output, never anything on the hosts, and is recorded in the security audit log. Known SSH authentication passwords and terminal control sequences are removed before storage. This is not a general secret detector: commands can print unrelated tokens, private data or other sensitive content. Run output is private to the owning account and is included in its stored history and backups. Avoid commands that print secrets.

A lost acknowledgement, missing exit status, timeout or cancellation after dispatch can mean **unknown**: the command may have taken effect. Inspect the target before retrying. Stop does not undo remote changes or guarantee remote process termination. Reaching the output capture or history limit only truncates the retained log: WebSSH continues draining stdout and stderr until the exit status, cancellation or timeout. Captured data is bounded to 128 KiB per stream before redaction and the smaller history budget is applied. A large stdout stream cannot consume stderr's capture allocation.

- Existing single-worker deployment contract remains; schedule claims additionally use transactional database compare-and-swap.
- One active run per user, four globally, with existing SSH/background quotas.
- At most 50 targets, 20 steps, 8192 UTF-8 bytes per command, 1–300 seconds per step and a 30-minute total deadline.
- At most 50 schedules per user. Preview intents last five minutes and are single-use.
- HTTPS, CSRF, action-bound account authorization, current destination bindings and verified SSH host keys remain mandatory.
- No automatic retries, rollback, agent forwarding, controller-local command execution or plugin/collection loading.

Prefer dedicated remote accounts with limited permissions. Never embed secrets in commands. Replacing a credential revokes its previous execution approvals; unrelated credential changes do not.

The UI uses the chosen theme and reduced-motion preference. Narrow views change the inspector arrangement instead of shrinking text. Activity and progress reflect confirmed execution state.
## Workflow examples

The Workflows landing page explains the steps-to-hosts-to-execution journey and offers 22 editable templates grouped into System, Network, Services and logs, Containers, and Packages. The selector previews the included steps, prerequisites, and whether the commands change the host.

Opening a template creates an unsaved draft with no destinations selected. It does not save a workflow, execute commands, or enable a schedule. Existing unsaved changes require confirmation before replacement. Templates begin with an explicit prerequisite check for the supported OS and required tools, plus systemd or Docker access where needed. A failed check stops that host before subsequent steps. Review and adapt every command for the destination OS and installed tools before saving and approving a run. Existing saved workflows are independent copies and are not rewritten by template updates; reopen a template to obtain its updated checks.

Most examples collect inventory or diagnostics. The Debian/Ubuntu and Fedora/RHEL upgrade examples modify installed packages, may restart services, and require noninteractive sudo permission. Their 300-second step timeout is a bound, not a completion guarantee; inspect the host after an uncertain result. Journal output may contain sensitive information and follows the same bounded history storage policy as other runs.

Saved command sets are available in a separate group in the template selector. Importing creates a copy as one shell step, preserving the resolved sequence and its shell context. Parameterized sets request fixed values and use the existing server-side parameter resolver. Missing references or oversized commands must be repaired before import. Later changes to the original set do not update a workflow copy.

Overview displays up to five recent runs, prioritizing queued and running jobs, with confirmed step counts and a direct link to the expanded run log. Status refreshes while Overview is visible; a failed refresh is marked as stale rather than shown as a successful result. The workflow action bar stays reachable while the editor and destination list scroll. Motion follows the reduced-motion preference.
