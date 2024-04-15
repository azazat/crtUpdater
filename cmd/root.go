/*
Copyright © 2024 azazat <EMAIL ADDRESS>
*/
package cmd

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	h "crtUpdater/internal/helper"

	"github.com/go-playground/validator/v10"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	Layout = "Jan _2 15:04:05 2006 MST"
)

var cfgFile string

type location struct {
	acmeDir           string
	certDir           string
	cerFilename       string
	keyFilename       string
	chainFilename     string
	fullchainFilename string
	deployDir         string
	cerCommercial     string
	keyCommercial     string
	caCommercial      string
}

type shellCmd struct {
	checkcrtexpiration  []string `validate:"required"`
	enableFwRule        []string `validate:"required"`
	issueCert           []string `validate:"required"`
	disableFwRule       []string `validate:"required"`
	createFullchainFile []string `validate:"required"`
	verifyCrts          []string `validate:"required"`
	deploy              []string `validate:"required"`
	restart             []string `validate:"required"`
}

var (
	l location
	s shellCmd
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "crtUpdater",
	Short: "A brief description of your application",
	Long:  `A longer description`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	Run: func(cmd *cobra.Command, args []string) {
		l = location{
			acmeDir:           "/root/.acme.sh/",
			certDir:           viper.GetStringSlice("domains")[0] + "/",
			cerFilename:       "/root/.acme.sh/" + viper.GetStringSlice("domains")[0] + "/" + viper.GetStringSlice("domains")[0] + ".cer",
			keyFilename:       "/root/.acme.sh/" + viper.GetStringSlice("domains")[0] + "/" + viper.GetStringSlice("domains")[0] + ".key",
			chainFilename:     "/root/.acme.sh/" + viper.GetStringSlice("domains")[0] + "/" + "fullchain.cer",
			fullchainFilename: "/root/.acme.sh/" + viper.GetStringSlice("domains")[0] + "/" + "fullchain.cer.full",
			deployDir:         "/opt/zimbra/ssl/zimbra/commercial/",
			cerCommercial:     "/opt/zimbra/ssl/zimbra/commercial/" + "commercial.cer",
			keyCommercial:     "/opt/zimbra/ssl/zimbra/commercial/" + "commercial.key",
			caCommercial:      "/opt/zimbra/ssl/zimbra/commercial/" + "commercial_ca.crt",
		}

		sc := []string{"--issue"}
		for _, i := range viper.GetStringSlice("domains") {
			sc = append(sc, "-d", i)
		}
		sc = append(sc, "--standalone", "--httpport", "88", "--keylength", "2048", "--force", "--server", "letsencrypt")

		s = shellCmd{
			checkcrtexpiration:  []string{"-c", "/opt/zimbra/bin/zmcertmgr checkcrtexpiration -days 100"},
			enableFwRule:        []string{viper.Get("mkr_user").(string) + "@" + viper.Get("mkr_host").(string), "ip firewall nat enable [find comment=\"" + viper.Get("mkr_comment").(string) + "\"]"},
			issueCert:           sc,
			disableFwRule:       []string{viper.Get("mkr_user").(string) + "@" + viper.Get("mkr_host").(string), "ip firewall nat disable [find comment=\"" + viper.Get("mkr_comment").(string) + "\"]"},
			createFullchainFile: []string{"-c", "cat /root/ISRG-X1.pem >>" + l.fullchainFilename},
			verifyCrts:          []string{"verifycrt", "comm", l.keyFilename, l.cerFilename, l.fullchainFilename},
			deploy:              []string{"deploycrt", "comm", l.cerCommercial, l.caCommercial},
			restart:             []string{"-c", "sudo -u zimbra /opt/zimbra/bin/zmcontrol restart"},
		}

		validate := validator.New(validator.WithRequiredStructEnabled())
		if err := validate.Struct(s); err != nil {
			log.Fatalf("Missing required attributes %v\n", err)
		}

		LOG_FILE := viper.Get("logfile")
		logFile, err := os.OpenFile(LOG_FILE.(string), os.O_APPEND|os.O_RDWR|os.O_CREATE, 0644)
		if err != nil {
			log.Panic(err)
		}
		defer logFile.Close()
		log.SetOutput(logFile)
		// optional: log date-time, filename, and line number
		log.SetFlags(log.Lshortfile | log.LstdFlags)
		log.Printf("\nLogging to custom file %s\n", LOG_FILE.(string))

		log.Println("All Keys: ", viper.AllKeys())
		log.Printf("Domains for cert: %+v", viper.Get("domains"))
		deadlineInDays := viper.Get("deadline")
		deadlineInHours := time.Duration(deadlineInDays.(int)) * time.Hour * 24
		if leftDays() < deadlineInHours {
			log.Printf("deadlineInHours: %s\n", deadlineInHours)
			log.Println("Certificate update is needed!!!")

			log.Println("ip firewall nat enable [find comment=\"" + viper.Get("mkr_comment").(string) + "\"]")

			enableFwRule()
			// рзаобраться со статусом ссш команды включеия правила
			// send pocket via telnet, catch it via tcpdump
			issueCert()
			disableFwRule()
			createFullchainFile()
			verifyCrts()
			backup()
			prepareFiles()
			deploy()
			restart()
		}
	},
}

func leftDays() time.Duration {
	cmd := exec.Command("/bin/bash", s.checkcrtexpiration...)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()

	if err != nil {
		//bash command exit status = 1
		log.Println("______________checkcrtexpiration______________")
		log.Println(fmt.Sprintf("%s - ignore this!\n", err) + "STDOUT checkcrtexpiration command: \n" + stdout.String())

	}
	lines := strings.Split(stdout.String(), "\n")
	expireraw := strings.Split(lines[1], "=")
	expirestring := expireraw[1]
	tm, _ := time.Parse(Layout, expirestring)
	until := time.Until(tm).Truncate(time.Minute)
	log.Println("Time until expire: ", until)
	return until
}

func enableFwRule() {
	log.Println("______________Enabling fw rule...______________")
	//bash command returns always 0 even if there is no such rule
	_, err := exec.Command("ssh", s.enableFwRule...).Output()
	if err != nil {
		log.Fatal(err)
	}
}

func issueCert() {
	log.Println("______________issuing certificate...______________")
	cmd3, err := exec.Command(l.acmeDir+"acme.sh", s.issueCert...).Output()
	if err != nil {
		log.Fatal(err)
	}
	log.Println(string(cmd3))
}

func disableFwRule() {
	log.Println("______________Disabling fw rule...______________")
	_, err := exec.Command("ssh", s.disableFwRule...).Output()
	if err != nil {
		log.Fatal(err)
	}
}

func createFullchainFile() {
	log.Println("______________Creating file for fullchain...______________")
	err := h.Copy(l.fullchainFilename, l.chainFilename)

	if err != nil {
		log.Fatal(err)
	}

	log.Println("______________Add ISRG to fullchain...______________")
	_, err = exec.Command("bash", s.createFullchainFile...).Output()

	if err != nil {
		log.Fatal(err)
	}
}

func verifyCrts() {
	log.Println("______________Verifying crt...______________")
	cmd, err := exec.Command("/opt/zimbra/bin/zmcertmgr", s.verifyCrts...).Output()
	if err != nil {
		log.Fatal(err)
	}
	log.Println(string(cmd))

	s1 := fmt.Sprintf("Certificate (%s) and private key (%s) match.", l.cerFilename, l.keyFilename)
	if strings.Contains(string(cmd), s1) {
		log.Println("Cert and Key match")
	} else {
		log.Fatal("Cert and Key NOT match")
	}

	s2 := fmt.Sprintf("Valid Certificate: %s: OK", l.cerFilename)
	if strings.Contains(string(cmd), s2) {
		log.Println("Valid cert")
	} else {
		log.Fatal("Invalid cert")
	}
}

func backup() {
	log.Println("______________Backup current crts...______________")
	currenttime := time.Now().Format("20060102-150405")
	path := l.deployDir + currenttime
	err := os.Mkdir(path, 0750)
	if err != nil {
		log.Fatal(err)
	}

	files := []string{l.caCommercial, l.cerCommercial, l.keyCommercial}
	separator := "/opt/zimbra/ssl/zimbra/commercial/"

	for _, fullName := range files {
		parts := strings.SplitAfter(fullName, separator)
		err = h.Copy(path+"/"+parts[1], fullName)
		if err != nil {
			log.Fatal(err)
		}
	}

}

func prepareFiles() {
	log.Println("______________Prepare new certs to deploy...______________")
	m := map[string]string{
		l.caCommercial:  l.fullchainFilename,
		l.cerCommercial: l.cerFilename,
		l.keyCommercial: l.keyFilename,
	}

	for dst, src := range m {
		err := h.Copy(dst, src)
		if err != nil {
			log.Fatal(err)
		}
	}
}

func deploy() {
	log.Println("______________DEPLOY______________")
	cmd, err := exec.Command("/opt/zimbra/bin/zmcertmgr", s.deploy...).Output()
	if err != nil {
		log.Fatal(err)
	}
	log.Println(string(cmd))
}

func restart() {
	log.Println("______________RESTART______________")
	cmd, err := exec.Command("bash", s.restart...).Output()
	if err != nil {
		log.Fatal(err)
	}
	log.Println(string(cmd))
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.crtUpdater.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		// Search config in home directory with name ".crtUpdater" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".crtUpdater")
	}
	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	} else {
		panic(fmt.Errorf("fatal error config file: %w", err))
	}
}
