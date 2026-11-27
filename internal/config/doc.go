// Package config reads the configuration of WebSSH from the environment.
//
// The Go release accepts every environment variable the Python release
// documents and gives each value the meaning it has there (decision D-14):
// the parsers reproduce Python's int(), str.strip(), str.lower(),
// ipaddress and urlsplit, and a configuration fails to start exactly where
// config.py raises, with the same message. Unusual spellings that keep
// their Python meaning, such as " true" (false) or "1_000", are reported
// as warnings. Variables without meaning in Go, such as the Gunicorn
// settings, are validated and reported as obsolete (D-16).
//
// The container start follows entrypoint.sh: ResolveDataDir canonicalizes
// DATA_DIR like os.path.realpath, ResolveSecretKey picks SECRET_KEY or
// DATA_DIR/secret_key or creates the file, and Load applies config.py to
// the result. Bootstrap runs the three in order.
//
// Beyond config.py the package reads TRUSTED_PROXY_CIDRS (D-19), the
// REQUESTS_CA_BUNDLE and CURL_CA_BUNDLE trust anchors, HOST and PORT, and
// reports a TZ the Go runtime cannot load. The production profile enforces
// the rules of validate_security_config.
//
// ReadDotenv and LoadDotenv read the .env file of the installation with
// the semantics of python-dotenv, as config.py does before it reads the
// environment.
//
// The differential tests compare the package with config.py and
// entrypoint.sh of the Python release; see oracle_test.go.
package config
