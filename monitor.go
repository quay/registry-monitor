package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/coreos/pkg/flagutil"
	"github.com/fsouza/go-dockerclient"
	"github.com/prometheus/client_golang/prometheus"

	log "github.com/sirupsen/logrus"
)

var listen = flag.String("listen", ":8000", "")
var level = flag.String("loglevel", "info", "default log level: debug, info, warn, error, fatal, panic")
var dockerUsername = flag.String("username", "", "Registry username for pulling and pushing")
var dockerPassword = flag.String("password", "", "Registry password for pulling and pushing")
var registryHost = flag.String("registry-host", "", "Hostname of the registry being monitored")
var repository = flag.String("repository", "", "Repository on the registry to pull and push")
var baseImage = flag.String("base-image", "", "Repository to use as base image for push image; instead of base-layer-id")
var publicBase = flag.Bool("public-base", false, "Is the base image public or private (default: false)")
var baseLayer = flag.String("base-layer-id", "", "Docker V1 ID of the base layer in the repository; instead of base-image")
var testInterval = flag.String("run-test-every", "2m", "the time between test in minutes")

var (
	base         string
	dockerClient *docker.Client
	dockerHost   string
	healthy      bool
	status       bool
)

var (
	promNamespace = os.Getenv("PROMETHEUS_NAMESPACE")

	promSuccessMetric = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: promNamespace,
		Subsystem: "",
		Name:      "monitor_success",
		Help:      "The registry monitor successfully completed a pull and push operation",
	}, []string{})

	promFailureMetric = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: promNamespace,
		Subsystem: "",
		Name:      "monitor_failure",
		Help:      "The registry monitor failed to complete a pull and push operation",
	}, []string{})

	promPushMetric = prometheus.NewSummary(prometheus.SummaryOpts{
		Namespace: promNamespace,
		Subsystem: "",
		Name:      "monitor_push",
		Help:      "The time for the monitor push operation",
	})

	promPullMetric = prometheus.NewSummary(prometheus.SummaryOpts{
		Namespace: promNamespace,
		Subsystem: "",
		Name:      "monitor_pull",
		Help:      "The time for the monitor pull operation",
	})
)

var prometheusMetrics = []prometheus.Collector{promSuccessMetric, promFailureMetric, promPullMetric, promPushMetric}

type LoggingWriter struct{}

func (w *LoggingWriter) Write(p []byte) (n int, err error) {
	s := string(p)
	log.Infof("%s", s)
	return len(s), nil
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	if !healthy {
		w.WriteHeader(503)
	}

	fmt.Fprintf(w, "%t", healthy)
}

func statusHandler(w http.ResponseWriter, r *http.Request) {
	if !status {
		w.WriteHeader(400)
	}

	fmt.Fprintf(w, "%t", status)
}

func buildTLSTransport(basePath string) (*http.Transport, error) {
	roots := x509.NewCertPool()
	pemData, err := ioutil.ReadFile(filepath.Join(basePath, "ca.pem"))
	if err != nil {
		return nil, err
	}

	// Add the certification to the pool.
	roots.AppendCertsFromPEM(pemData)

	// Create the certificate.
	crt, err := tls.LoadX509KeyPair(filepath.Join(basePath, "/cert.pem"), filepath.Join(basePath, "/key.pem"))
	if err != nil {
		return nil, err
	}

	// Create the new tls configuration using both the authority and certificate.
	conf := &tls.Config{
		RootCAs:      roots,
		Certificates: []tls.Certificate{crt},
	}

	// Create our own transport and return it.
	return &http.Transport{
		TLSClientConfig: conf,
	}, nil
}

func newDockerClient() (*docker.Client, error) {
	if os.Getenv("DOCKER_CERT_PATH") == "" {
		return docker.NewClient(dockerHost)
	}

	cert_path := os.Getenv("DOCKER_CERT_PATH")
	ca := fmt.Sprintf("%s/ca.pem", cert_path)
	cert := fmt.Sprintf("%s/cert.pem", cert_path)
	key := fmt.Sprintf("%s/key.pem", cert_path)
	return docker.NewTLSClient(dockerHost, cert, key, ca)
}

func stringInSlice(value string, list []string) bool {
	for _, current := range list {
		if current == value {
			return true
		}
	}
	return false
}

func verifyDockerClient(dockerClient *docker.Client) bool {
	log.Infof("Trying to connect to Docker client")
	if err := dockerClient.Ping(); err != nil {
		log.Errorf("Error connecting to Docker client: %s", err)
		healthy = false
		return false
	}

	log.Infof("Docker client valid")
	return true
}

func clearAllContainers(dockerClient *docker.Client) bool {
	listOptions := docker.ListContainersOptions{
		All: true,
	}

	log.Infof("Listing all containers")
	containers, err := dockerClient.ListContainers(listOptions)
	if err != nil {
		log.Errorf("Error listing containers: %s", err)
		healthy = false
		return false
	}

	for _, container := range containers {
		if stringInSlice("monitor", container.Names) {
			continue
		}

		log.Infof("Removing container: %s", container.ID)
		removeOptions := docker.RemoveContainerOptions{
			ID:            container.ID,
			RemoveVolumes: true,
			Force:         true,
		}

		if err = dockerClient.RemoveContainer(removeOptions); err != nil {
			log.Errorf("Error removing container: %s", err)
			healthy = false
			return false
		}
	}

	return healthy
}

func clearAllImages(dockerClient *docker.Client) bool {
	// Note: We delete in a loop like this because deleting one
	// image can lead to others being deleted. Therefore, we just
	// loop until the images list are empty.

	skipImages := map[string]bool{}

	for {
		// List all Docker images.
		listOptions := docker.ListImagesOptions{
			All: true,
		}

		log.Infof("Listing docker images")
		images, err := dockerClient.ListImages(listOptions)
		if err != nil {
			log.Errorf("Could not list images: %s", err)
			healthy = false
			return false
		}

		// Determine if we need to remove any images.
		imagesFound := false
		for _, image := range images {
			if _, toSkip := skipImages[image.ID]; toSkip {
				continue
			}

			imagesFound = true
		}

		if !imagesFound {
			return healthy
		}

		// Remove images.
		removedImages := false
		for _, image := range images[:1] {
			if _, toSkip := skipImages[image.ID]; toSkip {
				continue
			}

			log.Infof("Clearing image %s", image.ID)
			if err = dockerClient.RemoveImage(image.ID); err != nil {
				if strings.ToLower(os.Getenv("UNDER_DOCKER")) != "true" {
					log.Errorf("%s", err)
					healthy = false
					return false
				} else {
					log.Warningf("Skipping deleting image %v", image.ID)
					skipImages[image.ID] = true
					continue
				}
			}

			removedImages = true
		}

		if !removedImages {
			break
		}
	}

	return true
}

func pullTestImage(dockerClient *docker.Client) bool {
	pullOptions := docker.PullImageOptions{
		Repository:   *repository,
		Registry:     *registryHost,
		Tag:          "latest",
		OutputStream: &LoggingWriter{},
	}

	pullAuth := docker.AuthConfiguration{
		Username: *dockerUsername,
		Password: *dockerPassword,
	}

	if err := dockerClient.PullImage(pullOptions, pullAuth); err != nil {
		log.Errorf("Pull Error: %s", err)
		status = false
		return false
	}

	return true
}

func pullBaseImage(dockerClient *docker.Client) bool {
	pullOptions := docker.PullImageOptions{
		Repository:   *baseImage,
		Tag:          "latest",
		OutputStream: &LoggingWriter{},
	}

	var pullAuth docker.AuthConfiguration
	if *publicBase {
		pullAuth = docker.AuthConfiguration{}
	} else {
		pullAuth = docker.AuthConfiguration{
			Username: *dockerUsername,
			Password: *dockerPassword,
		}
	}

	if err := dockerClient.PullImage(pullOptions, pullAuth); err != nil {
		log.Errorf("Pull Error: %s", err)
		status = false
		return false
	}

	return true
}

func deleteTopLayer(dockerClient *docker.Client) bool {
	imageHistory, err := dockerClient.ImageHistory(*repository)
	if err != nil && err != docker.ErrNoSuchImage {
		log.Errorf("%s", err)
		healthy = false
		return false
	}

	for _, image := range imageHistory {
		if stringInSlice("latest", image.Tags) {
			log.Infof("Deleting image %s", image.ID)
			if err = dockerClient.RemoveImage(image.ID); err != nil {
				log.Errorf("%s", err)
				healthy = false
				return false
			}
			break
		}
	}

	return healthy
}

func createTagLayer(dockerClient *docker.Client) bool {
	t := time.Now().Local()
	timestamp := t.Format("2006-01-02 15:04:05 -0700")

	config := &docker.Config{
		Image: base,
		Cmd:   []string{"sh", "echo", "\"" + timestamp + "\" > foo"},
	}

	container_name := fmt.Sprintf("updatedcontainer%v", time.Now().Unix())
	log.Infof("Creating new image via container %v", container_name)

	options := docker.CreateContainerOptions{
		Name:   container_name,
		Config: config,
	}

	if _, err := dockerClient.CreateContainer(options); err != nil {
		log.Errorf("Error creating container: %s", err)
		healthy = false
		return false
	}

	commitOptions := docker.CommitContainerOptions{
		Container:  container_name,
		Repository: *repository,
		Tag:        "latest",
		Message:    "Updated at " + timestamp,
	}

	if _, err := dockerClient.CommitContainer(commitOptions); err != nil {
		log.Errorf("Error committing Container: %s", err)
		healthy = false
		return false
	}

	log.Infof("Removing container: %s", container_name)
	removeOptions := docker.RemoveContainerOptions{
		ID:            container_name,
		RemoveVolumes: true,
		Force:         true,
	}

	if err := dockerClient.RemoveContainer(removeOptions); err != nil {
		log.Errorf("Error removing container: %s", err)
		healthy = false
		return false
	}

	return healthy
}

func pushTestImage(dockerClient *docker.Client) bool {
	pushOptions := docker.PushImageOptions{
		Name:         *repository,
		Registry:     *registryHost,
		Tag:          "latest",
		OutputStream: &LoggingWriter{},
	}

	pushAuth := docker.AuthConfiguration{
		Username: *dockerUsername,
		Password: *dockerPassword,
	}

	if err := dockerClient.PushImage(pushOptions, pushAuth); err != nil {
		log.Errorf("Push Error: %s", err)
		status = false
		return false
	}

	status = true
	return true
}

func init() {
	dockerHost = os.Getenv("DOCKER_HOST")
	if dockerHost == "" {
		dockerHost = "unix:///var/run/docker.sock"
	}

	var err error
	dockerClient, err = newDockerClient()
	if err != nil {
		log.Fatalf("%s", err)
	}

}

func main() {
	// Parse the command line flags.
	if err := flag.CommandLine.Parse(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	if err := flagutil.SetFlagsFromEnv(flag.CommandLine, "REGISTRY_MONITOR"); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	lvl, err := log.ParseLevel(*level)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	log.SetLevel(lvl)

	// Ensure we have proper values.
	if *dockerUsername == "" {
		log.Fatalln("Missing username flag")
	}

	if *dockerPassword == "" {
		log.Fatalln("Missing password flag")
	}

	if *registryHost == "" {
		log.Fatalln("Missing registry-host flag")
	}

	if *repository == "" {
		log.Fatalln("Missing repository flag")
	}

	if *baseImage == "" && *baseLayer == "" {
		log.Infoln("Missing base-image and base-layer-id flag; Dynamically assigning base-layer-id")
		grabID, err := dockerClient.ImageHistory(*repository)
		if err != nil {
			log.Fatalf("Failed to grab image ID: %v", err)
		}
		log.Infof("Assigning base-layer-id to %s", grabID[0].ID)
		*baseLayer = grabID[0].ID
	} else if *baseImage != "" && *baseLayer != "" {
		log.Fatalln("Both base-image and base-layer-id flag; only one of required")
	}

	// Register the metrics.
	for _, metric := range prometheusMetrics {
		err := prometheus.Register(metric)
		if err != nil {
			log.Fatalf("Failed to register metric: %v", err)
		}
	}

	// Setup the HTTP server.
	http.Handle("/metrics", prometheus.Handler())
	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/status", statusHandler)

	log.Infoln("Listening on", *listen)

	// Run the monitor routine.
	runMonitor()

	// Listen and serve.
	log.Fatal(http.ListenAndServe(*listen, nil))
}

func runMonitor() {
	firstLoop := true
	healthy = true
	duration := 120 * time.Second
	mainLoop := func() {
		userDuration, err := time.ParseDuration(*testInterval)
		if err != nil {
			log.Fatalf("Failed to parse time interval: %v", err)
		}

		for {
			if !firstLoop {
				log.Infof("Sleeping for %v", duration)
				time.Sleep(duration)
			}

			log.Infof("Starting test")
			firstLoop = false
			status = true

			if dockerClient == nil || !verifyDockerClient(dockerClient) {
				log.Infof("Trying docker host: %s", dockerHost)
				dockerClient, err = newDockerClient()
				if err != nil {
					log.Errorf("%s", err)
					healthy = false
					return
				}
				if !verifyDockerClient(dockerClient) {
					return
				}
			}
			if strings.ToLower(os.Getenv("UNDER_DOCKER")) != "true" {
				log.Infof("Clearing all containers")
				if !clearAllContainers(dockerClient) {
					return
				}
			}
			if strings.ToLower(os.Getenv("UNDER_DOCKER")) != "true" {
				log.Infof("Clearing all images")
				if !clearAllImages(dockerClient) {
					return
				}
			}

			log.Infof("Pulling test image")
			pullStartTime := time.Now()
			if !pullTestImage(dockerClient) {
				duration = 30 * time.Second

				// Write the failure metric.
				m, err := promFailureMetric.GetMetricWithLabelValues()
				if err != nil {
					panic(err)
				}

				m.Inc()
				continue
			}

			// Write the pull time metric.
			promPullMetric.Observe(time.Since(pullStartTime).Seconds())

			if *baseImage != "" {
				log.Infof("Pulling specified base image")
				if !pullBaseImage(dockerClient) {
					return
				}
				base = *baseImage
			} else {
				base = *baseLayer
			}

			log.Infof("Deleting top layer")
			if !deleteTopLayer(dockerClient) {
				return
			}

			log.Infof("Creating new top layer")
			if !createTagLayer(dockerClient) {
				return
			}

			log.Infof("Pushing test image")
			pushStartTime := time.Now()
			if !pushTestImage(dockerClient) {
				duration = 30 * time.Second
				// Write the failure metric.
				m, err := promFailureMetric.GetMetricWithLabelValues()
				if err != nil {
					panic(err)
				}

				m.Inc()

				continue
			}

			// Write the push time metric.
			promPushMetric.Observe(time.Since(pushStartTime).Seconds())

			log.Infof("Test successful")
			duration = userDuration

			// Write the success metric.
			m, err := promSuccessMetric.GetMetricWithLabelValues()
			if err != nil {
				panic(err)
			}

			m.Inc()
		}
	}

	go mainLoop()
}
