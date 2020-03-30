package main

import (
	"encoding/json"
	"flag"
	"fmt"
	qt "github.com/QUIC-Tracker/quic-tracker"
	s "github.com/QUIC-Tracker/quic-tracker/scenarii"
	"math/rand"
	"os"
	"os/exec"
	"strings"
	"time"
)

var scenario_list = [34]string{"zero_rtt", "connection_migration", "unsupported_tls_version", "stream_opening_reordering", "multi_stream", "new_connection_id", "version_negotiation", "handshake", "handshake_v6", "transport_parameters", "address_validation", "padding", "flow_control", "ack_only", "ack_ecn", "stop_sending", "http_get_and_wait", "http_get_on_uni_stream", "key_update", "retire_connection_id", "http3_get", "http3_encoder_stream", "http3_uni_streams_limits", "http3_reserved_frames", "http3_reserved_streams", "spin_bit", "server_flow_control", "connection_migration_v4_v6", "zero_length_cid", "multi_packet_client_hello", "spurious_initial_packet", "random_sequence", "random_packet_sequence", "stream_reset_reordering"}
var host_list = [2]string{"quic.tech:8443", "fb.mvfst.net:443"}

func main() {
	qt.FuzzSession = true
	host := flag.String("host", "", "The host endpoint to run the test against.")
	path := flag.String("path", "/index.html", "The path to request when performing tests that needs data to be sent.")
	alpn := flag.String("alpn", "hq", "The ALPN prefix to use when connecting ot the endpoint.")
	// scenarioName := flag.String("scenario", "", "The particular scenario to run.")
	outputFile := flag.String("output", "", "The file to write the output to. Output to stdout if not set.")
	debug := flag.Bool("debug", false, "Enables debugging information to be printed.")
	nopcap := flag.Bool("nopcap", false, "Disables the pcap capture.")
	netInterface := flag.String("interface", "", "The interface to listen to when capturing pcap.")
	timeout := flag.Int("timeout", 10, "The amount of time in seconds spent when completing the test. Defaults to 10. When set to 0, the test ends as soon as possible.")
	flag.Parse()

	scenarioName := new(string)
	*scenarioName = scenario_list[rand.Intn(34)]
	// *scenarioName = list[4]
	// *scenarioName = "connection_migration"
	fmt.Println(*scenarioName)
	if *host == "" || *path == "" || *scenarioName == "" {
		println("Parameters host, path and scenario are required")
		os.Exit(-1)
	}

	scenario, ok := s.GetAllScenarii()[*scenarioName]
	if !ok {
		println("Unknown scenario", *scenarioName)
		return
	}

	trace := qt.NewTrace(scenario.Name(), scenario.Version(), *host)

	conn, err := qt.NewDefaultConnection(*host, strings.Split(*host, ":")[0], nil, scenario.IPv6(), *alpn, scenario.HTTP3()) // Raw IPv6 are not handled correctly

	if err == nil {
		var pcap *exec.Cmd
		if !*nopcap {
			pcap, err = qt.StartPcapCapture(conn, *netInterface)
			if err != nil {
				trace.Results["pcap_start_error"] = err.Error()
			}
		}

		trace.AttachTo(conn)

		start := time.Now()
		scenario.SetTimer(time.Duration(*timeout) * time.Second)
		scenario.Run(conn, trace, *path, *debug)
		trace.Duration = uint64(time.Now().Sub(start).Seconds() * 1000)
		ip := strings.Replace(conn.ConnectedIp().String(), "[", "", -1)
		trace.Ip = ip[:strings.LastIndex(ip, ":")]
		trace.StartedAt = start.Unix()

		trace.Complete(conn)
		conn.Close()
		if pcap != nil {
			err = trace.AddPcap(conn, pcap)
		}
		if err != nil {
			trace.Results["pcap_completed_error"] = err.Error()
		}
	} else {
		trace.ErrorCode = 255
		trace.Results["udp_error"] = err.Error()
	}

	out, _ := json.Marshal(trace)
	if *outputFile != "" {
		os.Remove(*outputFile)
		outFile, err := os.OpenFile(*outputFile, os.O_CREATE|os.O_WRONLY, 0755)
		defer outFile.Close()
		if err == nil {
			outFile.Write(out)
			return
		} else {
			println(err.Error())
		}
	}

	println(string(out))
}
