package httpapi

// Routes of the area "files" (FS1): the file workspace. Large editor and
// image answers are fetched over HTTP instead of the realtime connection;
// the route has no counterpart in the Python release.

var filesBuilt = []route{
	{"GET /api/files/handoff/{token}", AccessUser},
}
