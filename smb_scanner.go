package main

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	negotiateProtocolRequest, _  = hex.DecodeString(strings.ReplaceAll("zzzzzz85ff534d4272zzzzzzzz1853czzzzzzzzzzzzzzzzzzzzzzzzzzzzzfffezzzz4zzzzz62zzz25z432z4e4554574f524b2z5z524f4752414d2z312e3zzzz24c414e4d414e312e3zzzz257696e646f77732z666f722z576f726b67726f757z732z332e3161zzz24c4d312e32583z3z32zzz24c414e4d414e322e31zzz24e542z4c4d2z3z2e3132zz","z","0"))
	sessionSetupRequest, _       = hex.DecodeString(strings.ReplaceAll("zzzzzz88ff534d4273zzzzzzzz18z7czzzzzzzzzzzzzzzzzzzzzzzzzzzzzfffezzzz4zzzzdffzz88zzz411zazzzzzzzzzzzzzzz1zzzzzzzzzzzzzzd4zzzzzz4bzzzzzzzzzzzz57zz69zz6ezz64zz6fzz77zz73zz2zzz32zz3zzz3zzz3zzz2zzz32zz31zz39zz35zzzzzz57zz69zz6ezz64zz6fzz77zz73zz2zzz32zz3zzz3zzz3zzz2zzz35zz2ezz3zzzzzzz","z","0"))
	treeConnectRequest, _        = hex.DecodeString(strings.ReplaceAll("zzzzzz6zff534d4275zzzzzzzz18z7czzzzzzzzzzzzzzzzzzzzzzzzzzzzzfffezzz84zzzz4ffzz6zzzz8zzz1zz35zzzz5czz5czz31zz39zz32zz2ezz31zz36zz38zz2ezz31zz37zz35zz2ezz31zz32zz38zz5czz49zz5zzz43zz24zzzzzz3f3f3f3f3fzz","z","0"))
	transNamedPipeRequest, _     = hex.DecodeString(strings.ReplaceAll("zzzzzz4aff534d4225zzzzzzzz18z128zzzzzzzzzzzzzzzzzzzzzzzzzzz88ea3z1z852981zzzzzzzzzffffffffzzzzzzzzzzzzzzzzzzzzzzzz4azzzzzz4azzz2zz23zzzzzzz7zz5c5z495z455czz","z","0"))
	trans2SessionSetupRequest, _ = hex.DecodeString(strings.ReplaceAll("zzzzzz4eff534d4232zzzzzzzz18z7czzzzzzzzzzzzzzzzzzzzzzzzzzzz8fffezzz841zzzfzczzzzzzz1zzzzzzzzzzzzzza6d9a4zzzzzzzczz42zzzzzz4ezzz1zzzezzzdzzzzzzzzzzzzzzzzzzzzzzzzzzzz","z","0"))
)

type ScanStatus string

const (
	statusUnknown    = ScanStatus("?")
	statusVulnerable = ScanStatus("+")
	statusBackdored  = ScanStatus("!")
)

type Target struct {
	IP      string
	Netmask string
}

type Result struct {
	Netmask string
	IP      string
	Text    string
	Error   error
	Status  ScanStatus
}

func scanHost(t *Target) *Result {

	res := &Result{IP: t.IP, Netmask: t.Netmask}

	timeout := time.Second * 5
	conn, err := net.DialTimeout("tcp", t.IP+":445", timeout)
	if err != nil {
		res.Error = err
		return res
	}

	conn.SetDeadline(time.Now().Add(time.Second * 10))
	conn.Write(negotiateProtocolRequest)
	reply := make([]byte, 1024)
	if n, err := conn.Read(reply); err != nil || n < 36 {
		res.Error = err
		return res
	}

	if binary.LittleEndian.Uint32(reply[9:13]) != 0 {
		res.Error = err
		return res
	}

	conn.Write(sessionSetupRequest)

	n, err := conn.Read(reply)
	if err != nil || n < 36 {
		res.Error = err
		return res
	}

	if binary.LittleEndian.Uint32(reply[9:13]) != 0 {
		res.Status = statusUnknown
		res.Text = fmt.Sprintf("Can't authorize to SMB. Imposible to check is host vulnerable or not.")
		res.Error = err
		return res
	}

	var os string
	sessionSetupResponse := reply[36:n]
	if wordCount := sessionSetupResponse[0]; wordCount != 0 {
		byteCount := binary.LittleEndian.Uint16(sessionSetupResponse[7:9])
		if n != int(byteCount)+45 {
			fmt.Println("invalid session setup AndX response")
		} else {
			for i := 10; i < len(sessionSetupResponse)-1; i++ {
				if sessionSetupResponse[i] == 0 && sessionSetupResponse[i+1] == 0 {
					os = string(sessionSetupResponse[10:i])
					break
				}
			}
		}

	}
	userID := reply[32:34]
	treeConnectRequest[32] = userID[0]
	treeConnectRequest[33] = userID[1]
	conn.Write(treeConnectRequest)

	if n, err := conn.Read(reply); err != nil || n < 36 {
		res.Error = err
		return res
	}

	treeID := reply[28:30]
	transNamedPipeRequest[28] = treeID[0]
	transNamedPipeRequest[29] = treeID[1]
	transNamedPipeRequest[32] = userID[0]
	transNamedPipeRequest[33] = userID[1]

	conn.Write(transNamedPipeRequest)
	if n, err := conn.Read(reply); err != nil || n < 36 {
		res.Error = err
		return res
	}

	if reply[9] == 0x05 && reply[10] == 0x02 && reply[11] == 0x00 && reply[12] == 0xc0 {
		res.Status = statusVulnerable
		res.Text = fmt.Sprintf("Seems vulnerable for MS17-010. Operation System: %s.", strings.Replace(os, "\x00", "", -1))

		trans2SessionSetupRequest[28] = treeID[0]
		trans2SessionSetupRequest[29] = treeID[1]
		trans2SessionSetupRequest[32] = userID[0]
		trans2SessionSetupRequest[33] = userID[1]

		conn.Write(trans2SessionSetupRequest)

		if n, err := conn.Read(reply); err != nil || n < 36 {
			res.Error = err
			return res
		}

		if reply[34] == 0x51 {
			res.Status = statusBackdored
			res.Text += fmt.Sprintf(" Seems to be infected by DoublePulsar.")
		}
	}
	return res
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// func scanNetCIDR(netCIDR string) error {
// 	ip, ipNet, err := net.ParseCIDR(netCIDR)
// 	if err != nil {
// 		return err
// 	}
// 	var wg sync.WaitGroup
// 	for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); incIP(ip) {
// 		wg.Add(1)
// 		go func(ip string) {
// 			defer wg.Done()
// 			// scanHost(ip)
// 		}(ip.String())
// 	}
// 	wg.Wait()
// 	return nil
// }

func scanner(targets <-chan *Target, results chan<- *Result, verbose bool, wg *sync.WaitGroup) {
	defer wg.Done()
	for t := range targets {
		if verbose {
			fmt.Printf("[] Scanning target: %s\n", t.IP)
		}
		results <- scanHost(t)
	}
}

func reporter(results <-chan *Result, csv *os.File, verbose bool, wg *sync.WaitGroup) {
	defer wg.Done()
	for r := range results {
		if r.Text != "" {
			fmt.Printf("[%s] %s. %s\n", r.Status, r.IP, r.Text)
			csv.Write([]byte(r.Netmask + ";"))
			csv.Write([]byte(r.IP + ";"))
			csv.Write([]byte(fmt.Sprintf("[%s] %s\n", r.Status, r.Text)))
		}
	}
}

func main() {
	fmt.Println("EternalBlue scanner tool")
	host := flag.String("ip", "", "IP address")
	netmask := flag.String("net", "", "IP network address. Example: 10.0.1.0/24")
	workers := flag.Int("workers", 200, "Count of concurrent workers.")
	verbose := flag.Bool("verbose", false, "Verbose output")
	file := flag.String("file", "", "File with list of targets to scan. Each address or netmask on new line.")
	out := flag.String("out", "", "Output file with results of scan in CSV format. Example: results.csv")

	flag.Parse()

	targets := make(chan *Target, 100)
	results := make(chan *Result, 1)

	var wgWorkers sync.WaitGroup

	wgWorkers.Add(*workers)
	for w := 0; w < *workers; w++ {
		go scanner(targets, results, *verbose, &wgWorkers)
	}

	var csv *os.File

	if *out != "" {
		var err error
		csv, err = os.Create(*out)
		if err != nil {
			log.Fatal(err)
		}
		defer csv.Close()
	}

	var wgReporter sync.WaitGroup
	wgReporter.Add(1)
	go reporter(results, csv, *verbose, &wgReporter)

	if *host != "" {
		targets <- &Target{IP: *host}
	}

	if *netmask != "" {
		ip, ipNet, err := net.ParseCIDR(*netmask)
		if err != nil {
			log.Fatal(err)
		}

		for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); incIP(ip) {
			targets <- &Target{IP: ip.String(), Netmask: ipNet.String()}
		}
	}

	if *file != "" {
		f, err := os.Open(*file)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			if net.ParseIP(scanner.Text()) != nil {
				targets <- &Target{IP: scanner.Text()}
			} else {
				ip, ipNet, err := net.ParseCIDR(scanner.Text())
				if err != nil {
					log.Fatal(err)
				}
				for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); incIP(ip) {
					targets <- &Target{IP: ip.String(), Netmask: ipNet.String()}
				}
			}
		}
	}

	close(targets)
	wgWorkers.Wait()

	close(results)
	wgReporter.Wait()

}
