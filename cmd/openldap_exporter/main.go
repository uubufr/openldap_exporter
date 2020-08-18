package main

import (
	"log"
	"os"
	"time"
        "crypto/tls"
        "crypto/x509"
        "io/ioutil"
        "fmt"

	exporter "github.com/tomcz/openldap_exporter"

	"github.com/urfave/cli/v2"
	"github.com/urfave/cli/v2/altsrc"
)

const (
	promAddr = "promAddr"
	ldapAddr = "ldapAddr"
        ldapsAddr = "ldapsAddr"
        ldapPort = "ldapPort"
	ldapUser = "ldapUser"
	ldapPass = "ldapPass"
	interval = "interval"
	metrics  = "metrPath"
	config   = "config"
        caPath   = "caPath"
        certPath = "certPath"
        keyPath  = "keyPath"
        verify   = "verify"
)

func main() {
	flags := []cli.Flag{
		altsrc.NewStringFlag(&cli.StringFlag{
			Name:    promAddr,
			Value:   ":9330",
			Usage:   "Bind address for Prometheus HTTP metrics server",
			EnvVars: []string{"PROM_ADDR"},
		}),
		altsrc.NewStringFlag(&cli.StringFlag{
			Name:    metrics,
			Value:   "/metrics",
			Usage:   "Path on which to expose Prometheus metrics",
			EnvVars: []string{"METRICS_PATH"},
		}),
		altsrc.NewStringFlag(&cli.StringFlag{
			Name:    ldapAddr,
			Value:   "localhost",
			Usage:   "Address of OpenLDAP server",
			EnvVars: []string{"LDAP_ADDR"},
		}),
                altsrc.NewStringFlag(&cli.StringFlag{
                        Name:    ldapsAddr,
                        Value:   "localhost",
                        Usage:   "LDAPS Address of OpenLDAP server",
                        EnvVars: []string{"LDAPS_ADDR"},
                }),
                altsrc.NewStringFlag(&cli.StringFlag{
                        Name:    ldapPort,
                        Value:   "389",
                        Usage:   "LDAP port",
                        EnvVars: []string{"LDAPS_PORT"},
                }),
                altsrc.NewStringFlag(&cli.StringFlag{
                        Name:    caPath,
                        Value:   "ca.pem",
                        Usage:   "ca chain file path",
                        EnvVars: []string{"LDAP_CA"},
                }),
                altsrc.NewStringFlag(&cli.StringFlag{
                        Name:    certPath,
                        Value:   "cert.pem",
                        Usage:   "client certificate",
                        EnvVars: []string{"LDAP_CERT"},
                }),
                altsrc.NewStringFlag(&cli.StringFlag{
                        Name:    keyPath,
                        Value:   "cert.key",
                        Usage:   "private key",
                        EnvVars: []string{"LDAP_KEY"},
                }),
                altsrc.NewStringFlag(&cli.StringFlag{
                        Name:    verify,
                        Value:   "false",
                        Usage:   "check server cert",
                        EnvVars: []string{"LDAP_VERIFY"},
                }),
		altsrc.NewStringFlag(&cli.StringFlag{
			Name:    ldapUser,
			Usage:   "OpenLDAP bind username (optional)",
			EnvVars: []string{"LDAP_USER"},
		}),
		altsrc.NewStringFlag(&cli.StringFlag{
			Name:    ldapPass,
			Usage:   "OpenLDAP bind password (optional)",
			EnvVars: []string{"LDAP_PASS"},
		}),
		altsrc.NewDurationFlag(&cli.DurationFlag{
			Name:    interval,
			Value:   30 * time.Second,
			Usage:   "Scrape interval",
			EnvVars: []string{"INTERVAL"},
		}),
		&cli.StringFlag{
			Name:  config,
			Usage: "Optional configuration from a `YAML_FILE`",
		},
	}
	app := &cli.App{
		Name:            "openldap_exporter",
		Usage:           "Export OpenLDAP metrics to Prometheus",
		Before:          altsrc.InitInputSourceWithContext(flags, optionalYamlSourceFunc(config)),
		Version:         exporter.GetVersion(),
		HideHelpCommand: true,
		Flags:           flags,
		Action:          runMain,
	}
	if err := app.Run(os.Args); err != nil {
		log.Fatalln(err)
	}
}

func optionalYamlSourceFunc(flagFileName string) func(context *cli.Context) (altsrc.InputSourceContext, error) {
	return func(c *cli.Context) (altsrc.InputSourceContext, error) {
		filePath := c.String(flagFileName)
		if filePath != "" {
			return altsrc.NewYamlSourceFromFile(filePath)
		}
		return &altsrc.MapInputSource{}, nil
	}
}

func runMain(c *cli.Context) error {
        var tlsConfig *tls.Config
	log.Println("starting Prometheus HTTP metrics server on", c.String(promAddr))
	go exporter.StartMetricsServer(c.String(promAddr), c.String(metrics))

        if c.String(ldapAddr) != "" {
                ldapHost := fmt.Sprintf("%s:%d", c.String(ldapAddr), c.Int(ldapPort))
                log.Println("starting OpenLDAP scraper for", ldapHost)
		for range time.Tick(c.Duration(interval)) {
                       exporter.ScrapeMetrics(ldapHost, c.String(ldapUser), c.String(ldapPass))
                }
        } else if c.String(ldapsAddr) != "" {
		cert, err := tls.LoadX509KeyPair(c.String(certPath), c.String(keyPath))
        	if err != nil {
                        log.Println("unable to load certPath or keyPath")
                	return nil
        	}
	        tlsConfig = &tls.Config{
	                Certificates: []tls.Certificate{cert},
	                MinVersion:   tls.VersionTLS13,
	                CipherSuites: []uint16{
	                        tls.TLS_AES_256_GCM_SHA384,
	                        tls.TLS_CHACHA20_POLY1305_SHA256,
	                },
                        ServerName: c.String(ldapsAddr),
	        }
	        tlsConfig.BuildNameToCertificate()

	        if verify != "false" {
	                pool := x509.NewCertPool()
	                cabs, err := ioutil.ReadFile(c.String(caPath))
	                if err != nil {
                                log.Println("unable to read caPath")
	                        return nil
	                }
	                ok := pool.AppendCertsFromPEM(cabs)
	                if !ok {
	                        return nil
	                }
                        tlsConfig.InsecureSkipVerify = false
	                tlsConfig.RootCAs = pool
	        }
                ldapHost := fmt.Sprintf("%s:%d", c.String(ldapsAddr), c.Int(ldapPort))
                log.Println("starting secure OpenLDAP scraper for",ldapHost)

                for range time.Tick(c.Duration(interval)) {
         	       exporter.ScrapeSecureMetrics(ldapHost, c.String(ldapUser), c.String(ldapPass), tlsConfig)
	        }
	} else {
            log.Println("Error: neither ldapAddr or ldapsAddr are defined")
            return nil
        }

	return nil
}
