package main

// areaExtensions are the areas of the M2 build in a fixed order: one file
// wire_<area>.go each, so packages built in parallel never edit the same
// lines of the composition root (M2 plan, section 4.7). An area joins the
// build as an extension; an area without hooks changes nothing.
var areaExtensions = []func() extension{
	ldapArea,
	oidcArea,
	githubArea,
	accountsArea,
	sshextArea,
	gatewayArea,
	jobsArea,
	terminalArea,
	serveropsArea,
	discoveryArea,
	hostcontextArea,
	filesArea,
	sftpArea,
	smbArea,
	credentialsArea,
	transfersArea,
	commandsArea,
	automationArea,
	schedulesArea,
	backupArea,
	rotationArea,
	operationsArea,
	platformArea,
}

func init() {
	for _, area := range areaExtensions {
		register(area())
	}
}
