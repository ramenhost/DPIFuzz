package main

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	qt "github.com/QUIC-Tracker/quic-tracker"
	"github.com/QUIC-Tracker/quic-tracker/scenarii"
	"io/ioutil"
	"os"
	"os/exec"
	p "path"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

func main() {
	hostsFilename := flag.String("hosts", "", "A tab-separated file containing hosts, the paths used to request data to be sent and ports for negotiating h3.")
	scenarioName := flag.String("scenario", "", "A particular scenario to run. Run all of them if the parameter is missing.")
	traceDirectory := flag.String("trace-directory", "/tmp", "Location of the trace files.")
	netInterface := flag.String("interface", "", "The interface to listen to when capturing pcaps. Lets tcpdump decide if not set.")
	parallel := flag.Bool("parallel", false, "Runs each scenario against multiple hosts at the same time.")
	maxInstances := flag.Int("max-instances", 10, "Limits the number of parallel scenario runs.")
	randomise := flag.Bool("randomise", false, "Randomise the execution order of scenarii")
	timeout := flag.Int("timeout", 10, "The amount of time in seconds spent when completing a test. Defaults to 10. When set to 0, each test ends as soon as possible.")
	debug := flag.Bool("debug", false, "Enables debugging information to be printed.")
	fuzz := flag.Bool("fuzz", false, "Enable fuzzer.")
	iterations := flag.Int("iterations", 10, "Number of time we want to execute a scenario.")

	flag.Parse()

	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		println("No caller information")
		os.Exit(-1)
	}
	scenarioRunnerFilename := p.Join(p.Dir(filename), "scenario_runner.go")

	if *hostsFilename == "" {
		println("The hosts parameter is required")
		os.Exit(-1)
	}

	file, err := os.Open(*hostsFilename)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	scenariiInstances := scenarii.GetAllScenarii()

	var scenarioIds []string
	for scenarioId := range scenariiInstances {
		scenarioIds = append(scenarioIds, scenarioId)
	}
	if !*randomise {
		sort.Strings(scenarioIds)
	}

	if *scenarioName != "" && scenariiInstances[*scenarioName] == nil {
		println("Unknown scenario", *scenarioName)
	}

	wg := &sync.WaitGroup{}
	if !*parallel {
		*maxInstances = 1
	}
	semaphore := make(chan bool, *maxInstances)
	for i := 0; i < *maxInstances; i++ {
		semaphore <- true
	}
	for _, id := range scenarioIds {
		if *scenarioName != "" && *scenarioName != id {
			continue
		}
		scenario := scenariiInstances[id]
		os.MkdirAll(p.Join(*traceDirectory, id), os.ModePerm)
		sname := id
		for j := 0; j < *iterations; j++ {

			//Generating a random source to initialise math/rand
			b := make([]byte, 8)
			n, err := rand.Read(b)
			if n != 8 {
				panic(n)
			} else if err != nil {
				panic(err)
			}
			s_ini := binary.BigEndian.Uint64(b)
			source := int64(s_ini)
			iter := j

			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := strings.Split(scanner.Text(), "\t")
				host, path := line[0], line[1]
				h3port, err := strconv.Atoi(line[2])
				if err != nil {
					println(err)
					continue
				}
				preferredALPN := line[3]

				if scenario.HTTP3() {
					split := strings.Split(host, ":")
					host, _ = split[0], split[1]
					host = fmt.Sprintf("%s:%d", host, h3port)
				}

				<-semaphore
				wg.Add(1)
				if *debug {
					fmt.Println("starting", scenario.Name(), "against", host)
				}

				go func() {
					defer func() { semaphore <- true }()
					defer wg.Done()

					outputFile, err := ioutil.TempFile("", "quic_tracker")
					if err != nil {
						println(err.Error())
						return
					}
					outputFile.Close()

					crashTrace := GetCrashTrace(scenario, host) // Prepare one just in case
					start := time.Now()

					args := []string{"run", scenarioRunnerFilename, "-host", host, "-path", path, "-alpn", preferredALPN, "-scenario", sname, "-interface", *netInterface, "-output", outputFile.Name(), "-timeout", strconv.Itoa(*timeout), "-source", strconv.FormatInt(source, 10), "-fuzz", strconv.FormatBool(*fuzz)}
					if *debug {
						args = append(args, "-debug")
					}

					c := exec.Command("go", args...)
					err = c.Run()
					if err != nil {
						println(err.Error())
					}

					var trace qt.Trace
					outputFile, err = os.Open(outputFile.Name())
					if err != nil {
						println(err)
					}
					defer outputFile.Close()
					defer os.Remove(outputFile.Name())

					err = json.NewDecoder(outputFile).Decode(&trace)
					if err != nil {
						println(err.Error())
						crashTrace.StartedAt = start.Unix()
						crashTrace.Duration = uint64(time.Now().Sub(start).Seconds() * 1000)
						// result <- crashTrace
						return
					}

					traceFile, err := os.Create(p.Join(*traceDirectory, sname, host+"_"+strconv.Itoa(iter)))
					if err != nil {
						println(err.Error())
						return
					}
					defer traceFile.Close()

					out, _ := json.Marshal(trace)
					traceFile.Write(out)

					// result <- &trace
				}()
			}
			file.Seek(0, 0)
		}
	}
	wg.Wait()

}

func GetCrashTrace(scenario scenarii.Scenario, host string) *qt.Trace {
	trace := qt.NewTrace(scenario.Name(), scenario.Version(), host)
	trace.ErrorCode = 254
	return trace
}
