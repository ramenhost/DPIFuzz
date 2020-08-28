//Experimental: Designed for Modular Fuzzer

package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	qt "github.com/QUIC-Tracker/quic-tracker"
	// "github.com/QUIC-Tracker/quic-tracker/fuzzer"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	p "path"
	"runtime"
	//"sort"
	"strconv"
	"strings"
	"sync"
	// "time"
)

// ConcurrentSlice type that can be safely shared between goroutines
type ConcurrentSlice struct {
	sync.RWMutex
	items []interface{}
}

// ConcurrentSliceItem contains the index/value pair of an item in a
// concurrent slice
type ConcurrentSliceItem struct {
	Index int
	Value interface{}
}

// NewConcurrentSlice creates a new concurrent slice
func NewConcurrentSlice() *ConcurrentSlice {
	cs := &ConcurrentSlice{
		items: make([]interface{}, 0),
	}

	return cs
}

// Append adds an item to the concurrent slice
func (cs *ConcurrentSlice) Append(item interface{}) {
	cs.Lock()
	defer cs.Unlock()

	cs.items = append(cs.items, item)
}

// Iter iterates over the items in the concurrent slice
// Each item is sent over a channel, so that
// we can iterate over the slice using the builin range keyword
func (cs *ConcurrentSlice) Iter() <-chan ConcurrentSliceItem {
	c := make(chan ConcurrentSliceItem)

	f := func() {
		cs.Lock()
		defer cs.Unlock()
		for index, value := range cs.items {
			c <- ConcurrentSliceItem{index, value}
		}
		close(c)
	}
	go f()

	return c
}

type ConcurrentMap struct {
	sync.RWMutex
	items map[string]interface{}
}

// ConcurrentMapItem contains a key/value pair item of a concurrent map
type ConcurrentMapItem struct {
	Key   string
	Value interface{}
}

// NewConcurrentMap creates a new concurrent map
func NewConcurrentMap() *ConcurrentMap {
	cm := &ConcurrentMap{
		items: make(map[string]interface{}),
	}

	return cm
}

// Set adds an item to a concurrent map
func (cm *ConcurrentMap) Set(key string, value interface{}) {
	cm.Lock()
	defer cm.Unlock()

	cm.items[key] = value
}

// Get retrieves the value for a concurrent map item
func (cm *ConcurrentMap) Get(key string) (interface{}, bool) {
	cm.Lock()
	defer cm.Unlock()

	value, ok := cm.items[key]

	return value, ok
}

// Iter iterates over the items in a concurrent map
// Each item is sent over a channel, so that
// we can iterate over the map using the builtin range keyword
func (cm *ConcurrentMap) Iter() <-chan ConcurrentMapItem {
	c := make(chan ConcurrentMapItem)

	f := func() {
		cm.Lock()
		defer cm.Unlock()

		for k, v := range cm.items {
			c <- ConcurrentMapItem{k, v}
		}
		close(c)
	}
	go f()

	return c
}

func main() {
	hostsFilename := flag.String("hosts", "", "A tab-separated file containing hosts, the paths used to request data to be sent and ports for negotiating h3.")
	generatorName := flag.String("generator", "", "A particular generator to use. Use all of them if the parameter is missing.")
	traceDirectory := flag.String("trace-directory", "/tmp", "Location of the trace files.")
	netInterface := flag.String("interface", "", "The interface to listen to when capturing pcaps. Lets tcpdump decide if not set.")
	parallel := flag.Bool("parallel", false, "Runs each fuzzer instance against multiple hosts at the same time.")
	maxInstances := flag.Int("max-instances", 2, "Limits the number of parallel fuzzer runs.")
	// randomise := flag.Bool("randomise", false, "Randomise the execution order of scenarii")
	timeout := flag.Int("timeout", 20, "The amount of time in seconds spent when completing a test. Defaults to 10. When set to 0, each test ends as soon as possible.")
	debug := flag.Bool("debug", false, "Enables debugging information to be printed.")
	fuzz := flag.Int("fuzz", 0, "Enable fuzzer.")
	iterations := flag.Int("iterations", 1, "Number of times we want to execute a the fuzzer with a specific generator against a host.")
	flag.Parse()

	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		println("No caller information")
		os.Exit(-1)
	}
	fuzzerRunnerFilename := p.Join(p.Dir(filename), "fuzzer_runner.go")

	fmt.Println(*parallel)
	fmt.Println(*maxInstances)
	fmt.Println(*iterations)

	if *hostsFilename == "" {
		println("The hosts parameter is required")
		os.Exit(-1)
	}

	file, err := os.Open(*hostsFilename)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	//Determining the number of hosts
	var hostCount int = 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		hostCount += 1
	}
	file.Seek(0, 0)

	m := NewConcurrentMap() //map to store seed values with scenario name and iteration number

	generatorList := []string{"stream_reassembly", "flow_control_stream_reassembly", "overlapping_offset"}

	wg := &sync.WaitGroup{}
	if !*parallel {
		*maxInstances = 1
	}
	semaphore := make(chan bool, *maxInstances)
	for i := 0; i < *maxInstances; i++ {
		semaphore <- true
	}
	for _, id := range generatorList {
		if *generatorName != "" && *generatorName != id {
			continue
		}

		gname := id
		os.MkdirAll(p.Join(*traceDirectory, gname), os.ModePerm)
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
			if source < 0 {
				source = -1 * source
			}
			iter := j

			//storing the source in the map
			m.Set(gname+"_"+strconv.Itoa(iter), source)

			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := strings.Split(scanner.Text(), "\t")
				host, path := line[0], line[1]
				// h3port, err := strconv.Atoi(line[2])
				if err != nil {
					println(err)
					continue
				}
				preferredALPN := line[3]

				<-semaphore
				wg.Add(1)
				if *debug {
					fmt.Println("starting fuzzer with generator ", id, " against ", host)
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

					args := []string{"run", fuzzerRunnerFilename, "-host", host, "-path", path, "-alpn", preferredALPN, "-generator", gname, "-interface", *netInterface, "-output", outputFile.Name(), "-timeout", strconv.Itoa(*timeout), "-source", strconv.FormatInt(source, 10), "-fuzz", strconv.Itoa(*fuzz)}
					if *debug {
						args = append(args, "-debug")
					}

					c := exec.Command("go", args...)
					var out bytes.Buffer
					var stderr bytes.Buffer
					c.Stdout = &out
					c.Stderr = &stderr
					err = c.Run()
					if err != nil {
						fmt.Println(fmt.Sprint(err) + ": " + stderr.String())
						println(err.Error())
					}

					var trace qt.Trace
					outputFile, err = os.Open(outputFile.Name())
					if err != nil {
						println(err)
					}
					defer outputFile.Close()
					defer os.Remove(outputFile.Name())

					traceFile, err := os.Create(p.Join(*traceDirectory, gname, host+"_"+strconv.Itoa(iter)))
					if err != nil {
						println(err.Error())
						return
					}
					defer traceFile.Close()

					err = json.NewDecoder(outputFile).Decode(&trace)
					if err != nil {
						println(err.Error())
						// crashTrace.StartedAt = start.Unix()
						// crashTrace.Duration = uint64(time.Now().Sub(start).Seconds() * 1000)
						// out, _ := json.Marshal(crashTrace)
						// traceFile.Write(out)
						return
					}

					//pick any part of trace that you want to compare between different hosts and write it to the file
					out_3, _ := json.Marshal(trace.Results["StreamDataReassembly"])
					out_1, _ := json.Marshal(trace.ErrorCode)

					fmt.Println("Data: ", string(out_3), " Seed:", source, "ErrorCode:", string(out_1))
					// 	out_2, _ := json.Marshal(trace.DiffCodes)
					if len(out_1) != 0 {
						traceFile.Write(out_1)
					}
					// 	if len(out_2) != 0 {
					// 		traceFile.Write(out_2)
					// 	}
					traceFile.Write(out_3)
				}()
			}
			file.Seek(0, 0)
		}
	}
	wg.Wait()

	//check for the number of hosts first. Proceed if > 1
	if hostCount > 1 {
		//The commented code can be used to print all the seed values for a particular execution of DPIFuzz
		// seedMap := make(map[string]int64)
		// for val := range m.Iter() {
		// 	seedMap[val.Key] = val.Value.(int64)
		// }

		// //creating files
		// seedFile, err := os.Create(p.Join(p.Dir(filename), "seed_map.txt"))
		// if err != nil {
		// 	println(err.Error())
		// }
		// defer seedFile.Close()
		// seedResult, err := json.Marshal(seedMap)
		// if err != nil {
		// 	println(err.Error())
		// 	return
		// }
		// seedFile.Write(seedResult)
		resultList := getFuzzerResultsSequential(generatorName, generatorList, hostsFilename, *iterations, maxInstances, traceDirectory, m)
		//creating files
		resultFile, err := os.Create(p.Join(p.Dir(filename), "comparison_results.txt"))
		if err != nil {
			println(err.Error())
		}
		defer resultFile.Close()
		resultFile.WriteString(resultList)
	}

	return
}

//test function to concurrently compute and compare hash values. Prototype stage
func getFuzzerResults(generatorName *string, generatorList []string, hostsFilename *string, iterations int, maxInstances *int, traceDirectory *string) []string {
	var result []string

	s := NewConcurrentSlice()
	m := NewConcurrentMap()
	flag_map := NewConcurrentMap()

	file, err := os.Open(*hostsFilename)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	wg := &sync.WaitGroup{}

	semaphore := make(chan bool, *maxInstances)
	for i := 0; i < *maxInstances; i++ {
		semaphore <- true
	}
	for _, id := range generatorList {
		if *generatorName != "" && *generatorName != id {
			continue
		}
		// scenario := scenariiInstances[id]
		gname := id

		for j := 0; j < iterations; j++ {
			scanner := bufio.NewScanner(file)
			iter := j
			for scanner.Scan() {
				line := strings.Split(scanner.Text(), "\t")
				host, _ := line[0], line[1]
				// h3port, err := strconv.Atoi(line[2])
				if err != nil {
					println(err)
					continue
				}

				// if scenario.HTTP3() {
				// 	split := strings.Split(host, ":")
				// 	host, _ = split[0], split[1]
				// 	host = fmt.Sprintf("%s:%d", host, h3port)
				// }

				<-semaphore
				wg.Add(1)
				go func() {
					defer func() { semaphore <- true }()
					defer wg.Done()

					//calculating hash values
					f, err := os.Open(p.Join(*traceDirectory, gname, host+"_"+strconv.Itoa(iter)))
					if err != nil {
						println(err.Error())
						return
					}
					defer f.Close()
					h := sha256.New()
					if _, err := io.Copy(h, f); err != nil {
						println(err)
					}

					hash := h.Sum(nil)
					m_val, success := m.Get(gname + "_" + strconv.Itoa(iter))
					if success != false {
						if bytes.Compare(hash, m_val.([]byte)) != 0 {
							if _, res := flag_map.Get(gname + "_" + strconv.Itoa(iter)); res == false {
								flag_map.Set(gname+"_"+strconv.Itoa(iter), true)
								s.Append(gname + "_" + strconv.Itoa(iter))
							}
						}
					} else {
						m.Set(gname+"_"+strconv.Itoa(iter), hash)
					}

				}()
			}
			file.Seek(0, 0)

		}
	}
	wg.Wait()
	for val := range s.Iter() {
		result = append(result, val.Value.(string))
	}
	return result
}

func getFuzzerResultsSequential(generatorName *string, generatorList []string, hostsFilename *string, iterations int, maxInstances *int, traceDirectory *string, seedMap *ConcurrentMap) string {

	type hosthash struct {
		host string
		hash []byte
	}

	m := make(map[string][]hosthash) //map to store the hash values of trace files of different hosts corresponding to a particular iteration of a fuzzer with a specific generator

	file, err := os.Open(*hostsFilename)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	for _, id := range generatorList {
		if *generatorName != "" && *generatorName != id {
			continue
		}
		gname := id

		for j := 0; j < iterations; j++ {
			scanner := bufio.NewScanner(file)
			iter := j
			for scanner.Scan() {
				line := strings.Split(scanner.Text(), "\t")
				host, _ := line[0], line[1]

				//calculating hash values
				f, err := os.Open(p.Join(*traceDirectory, gname, host+"_"+strconv.Itoa(iter)))
				h := sha256.New()
				if err != nil {
					println(err.Error())
					m[gname+"_"+strconv.Itoa(iter)] = append(m[gname+"_"+strconv.Itoa(iter)], hosthash{host, h.Sum(nil)})
					f.Close()
					continue
				}
				if _, err := io.Copy(h, f); err != nil {
					println(err)
				}
				f.Close()
				hash := h.Sum(nil)
				m[gname+"_"+strconv.Itoa(iter)] = append(m[gname+"_"+strconv.Itoa(iter)], hosthash{host, hash})
			}
			file.Seek(0, 0)
		}
	}
	//comparing hash values
	res := ""
	for key, val := range m {
		res += key
		res += "\t"
		seed, success := seedMap.Get(key)
		if success == false {
			continue
		}
		res += strconv.FormatInt(seed.(int64), 10) + "\t"
		l := len(val)
		for i := 0; i < l; i++ {
			res += val[i].host
			res += "--"
			for j := 0; j < l; j++ {
				if bytes.Compare(val[i].hash, val[j].hash) != 0 {
					res += val[j].host
					res += ","
				}
			}
			res += "\t\t"
		}
		res += "\n"
	}
	return res
}

// func GetCrashTrace(scenario scenarii.Scenario, host string) *qt.Trace {
// 	trace := qt.NewTrace(scenario.Name(), scenario.Version(), host)
// 	trace.ErrorCode = 254
// 	return trace
// }
