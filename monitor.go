package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/service/cloudwatch"
	"github.com/fsouza/go-dockerclient"
)

var (
	healthy bool
	status  bool
)

var (
	dockerUsername = os.Getenv("USERNAME")
	dockerPassword = os.Getenv("PASSWORD")
	registryName   = os.Getenv("REGISTRY_HOST")
	repository     = os.Getenv("REPOSITORY_NAME")
	baseLayer      = os.Getenv("BASE_IMAGE_ID")

	cloudwatchNamespace = os.Getenv("CLOUDWATCH_NAMESPACE")
	cloudwatchSuccess   = "MonitorSuccess"
	cloudwatchFailure   = "MonitorFailure"
	cloudwatchPushTime  = "MonitorPushTime"
	cloudwatchPullTime  = "MonitorPullTime"

	awsAccessKey = os.Getenv("AWS_ACCESS_KEY_ID")
	awsSecretKey = os.Getenv("AWS_SECRET_ACCESS_KEY")
	awsRegion    = os.Getenv("AWS_DEFAULT_REGION")
)

type LoggingWriter struct{}

func (w *LoggingWriter) Write(p []byte) (n int, err error) {
	s := string(p)
	log.Printf("%s", s)
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

func newDockerClient(dockerHost string) (*docker.Client, error) {
	host, err := url.Parse(dockerHost)
	if err != nil {
		return nil, err
	}

	// Change to an https connection if we have a cert path.
	if os.Getenv("DOCKER_CERT_PATH") != "" {
		host.Scheme = "https"
	}

	c, err := docker.NewClient(host.String())
	if err != nil {
		return nil, err
	}

	if os.Getenv("DOCKER_CERT_PATH") != "" {
		transport, err := buildTLSTransport(os.Getenv("DOCKER_CERT_PATH"))
		if err != nil {
			return nil, err
		}

		c.HTTPClient = &http.Client{Transport: transport}
	}

	return c, nil
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
	if err := dockerClient.Ping(); err != nil {
		log.Printf("%s", err)
		healthy = false
		return false
	}

	return true
}

func clearAllContainers(dockerClient *docker.Client) bool {
	listOptions := docker.ListContainersOptions{
		All: true,
	}

	containers, err := dockerClient.ListContainers(listOptions)
	if err != nil {
		log.Printf("%s", err)
		healthy = false
		return false
	}

	for _, container := range containers {
		if stringInSlice("monitor", container.Names) {
			continue
		}

		removeOptions := docker.RemoveContainerOptions{
			ID:            container.ID,
			RemoveVolumes: true,
			Force:         true,
		}

		if err = dockerClient.RemoveContainer(removeOptions); err != nil {
			log.Printf("%s", err)
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
	for {
		listOptions := docker.ListImagesOptions{
			All: true,
		}

		images, err := dockerClient.ListImages(listOptions)
		if err != nil {
			log.Printf("%s", err)
			healthy = false
			return false
		}

		if len(images) == 0 {
			return healthy
		}

		for _, image := range images[:1] {
			log.Printf("Clearing image %s", image.ID)
			if err = dockerClient.RemoveImage(image.ID); err != nil {
				log.Printf("%s", err)
				healthy = false
				return false
			}
		}
	}

	return healthy
}

func pullTestImage(dockerClient *docker.Client) bool {
	pullOptions := docker.PullImageOptions{
		Repository:   repository,
		Registry:     "quay.io",
		Tag:          "latest",
		OutputStream: &LoggingWriter{},
	}

	pullAuth := docker.AuthConfiguration{
		Username: dockerUsername,
		Password: dockerPassword,
	}

	if err := dockerClient.PullImage(pullOptions, pullAuth); err != nil {
		log.Printf("Pull Error: %s", err)
		status = false
		return false
	}

	return true
}

func deleteTopLayer(dockerClient *docker.Client) bool {
	imageHistory, err := dockerClient.ImageHistory(repository)
	if err != nil {
		log.Printf("%s", err)
		healthy = false
		return false
	}

	for _, image := range imageHistory {
		if stringInSlice("latest", image.Tags) {
			log.Printf("Deleting image %s", image.ID)
			if err = dockerClient.RemoveImage(image.ID); err != nil {
				log.Printf("%s", err)
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
		Image: baseLayer,
		Cmd:   []string{"sh", "echo", "\"" + timestamp + "\" > foo"},
	}

	options := docker.CreateContainerOptions{
		Name:   "updatedcontainer",
		Config: config,
	}

	if _, err := dockerClient.CreateContainer(options); err != nil {
		log.Printf("Create Container: %s", err)
		healthy = false
		return false
	}

	commitOptions := docker.CommitContainerOptions{
		Container:  "updatedcontainer",
		Repository: repository,
		Tag:        "latest",
		Message:    "Updated at " + timestamp,
	}

	if _, err := dockerClient.CommitContainer(commitOptions); err != nil {
		log.Printf("Commit Container: %s", err)
		healthy = false
		return false
	}

	return healthy
}

func pushTestImage(dockerClient *docker.Client) bool {
	pushOptions := docker.PushImageOptions{
		Name:         repository,
		Registry:     registryName,
		Tag:          "latest",
		OutputStream: &LoggingWriter{},
	}

	pushAuth := docker.AuthConfiguration{
		Username: dockerUsername,
		Password: dockerPassword,
	}

	if err := dockerClient.PushImage(pushOptions, pushAuth); err != nil {
		log.Printf("Push Error: %s", err)
		status = false
		return false
	}

	status = true
	return true
}

func putMetric(metricName string, watchService *cloudwatch.CloudWatch, unitName string, metricValue float64) {
	if watchService == nil {
		return
	}

	params := &cloudwatch.PutMetricDataInput{
		MetricData: []*cloudwatch.MetricDatum{
			&cloudwatch.MetricDatum{
				MetricName: aws.String(metricName),
				Timestamp:  aws.Time(time.Now()),
				Unit:       aws.String(unitName),
				Value:      aws.Float64(metricValue),
			},
		},
		Namespace: aws.String(cloudwatchNamespace),
	}

	_, err := watchService.PutMetricData(params)
	if err != nil {
		log.Printf("Failure to put cloudwatch metric: %s", err)
	}
}

func main() {
	if dockerUsername == "" {
		fmt.Println("Missing USERNAME env var")
		return
	}

	if dockerPassword == "" {
		fmt.Println("Missing PASSWORD env var")
		return
	}

	if registryName == "" {
		fmt.Println("Missing REGISTRY_HOST env var")
		return
	}

	if repository == "" {
		fmt.Println("Missing REPOSITORY_NAME env var")
		return
	}

	if baseLayer == "" {
		fmt.Println("Missing BASE_IMAGE_ID env var")
		return
	}

	var watchService *cloudwatch.CloudWatch = nil
	if awsAccessKey != "" && awsSecretKey != "" && awsRegion != "" && cloudwatchNamespace != "" {
		aws_creds := credentials.NewStaticCredentials(awsAccessKey, awsSecretKey, "")
		watchService = cloudwatch.New(&aws.Config{Region: aws.String(awsRegion), Credentials: aws_creds})
	}

	dockerHost := os.Getenv("DOCKER_HOST")
	if dockerHost == "" {
		dockerHost = "unix:///var/run/docker.sock"
	}

	firstLoop := true

	mainLoop := func() {
		duration := 2 * time.Minute

		for {
			if !firstLoop {
				log.Printf("Sleeping for %v", duration)
				time.Sleep(duration)
			}

			log.Printf("Starting test")
			firstLoop = false
			status = true

			log.Printf("Trying docker host: %s", dockerHost)
			dockerClient, err := newDockerClient(dockerHost)
			if err != nil {
				log.Printf("%s", err)
				healthy = false
				return
			}

			log.Printf("Clearing all containers")
			if !clearAllContainers(dockerClient) {
				return
			}

			log.Printf("Clearing all images")
			if !clearAllImages(dockerClient) {
				return
			}

			log.Printf("Pulling test image")
			pullStartTime := time.Now()
			if !pullTestImage(dockerClient) {
				duration = 30 * time.Second
				putMetric(cloudwatchFailure, watchService, "Count", 1)
				continue
			}
			putMetric(cloudwatchPullTime, watchService, "Seconds", time.Since(pullStartTime).Seconds())

			log.Printf("Deleting top layer")
			if !deleteTopLayer(dockerClient) {
				return
			}

			log.Printf("Creating new top layer")
			if !createTagLayer(dockerClient) {
				return
			}

			log.Printf("Pushing test image")
			pushStartTime := time.Now()
			if !pushTestImage(dockerClient) {
				duration = 30 * time.Second
				putMetric(cloudwatchFailure, watchService, "Count", 1)
				continue
			}
			putMetric(cloudwatchPushTime, watchService, "Seconds", time.Since(pushStartTime).Seconds())

			log.Printf("Test successful")
			duration = 2 * time.Minute
			putMetric(cloudwatchSuccess, watchService, "Count", 1)
		}
	}

	go mainLoop()

	// Run a simple HTTP server to report health and status.
	healthy = true
	status = true

	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/status", statusHandler)
	http.ListenAndServe(":8000", nil)
}
