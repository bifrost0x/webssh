package platform

// sd_notify(3) states WebSSH sends.
const (
	NotifyReady    = "READY=1"
	NotifyStopping = "STOPPING=1"
)
