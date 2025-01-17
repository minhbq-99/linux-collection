package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/urfave/cli/v2"
)

var readTimeout = 100 * time.Millisecond

type packetInOut struct {
	sentPacket     int
	receivedPacket int
}

func clientRoutine(
	serverAddress string,
	packetSize uint64,
	wg *sync.WaitGroup,
	inOut *packetInOut,
	stop chan struct{},
) {
	defer wg.Done()

	packet := make([]byte, packetSize)
	for i := 0; i < len(packet); i++ {
		packet[i] = 'A'
	}
	readBuffer := make([]byte, packetSize)

	client, err := net.Dial("tcp", serverAddress)
	if err != nil {
		fmt.Printf("Failed to connect to server: %v\n", err)
		return
	}
	defer client.Close()

LOOP:
	for {
		n, err := client.Write(packet)
		if err != nil {
			fmt.Printf("Failed to send packet: %v\n", err)
			return
		}
		if n != int(packetSize) {
			fmt.Printf("Packet is not completed, sent bytes: %d\n", n)
			return
		}
		inOut.sentPacket++

		for {
			select {
			case <-stop:
				break LOOP
			default:
			}
			client.SetReadDeadline(time.Now().Add(readTimeout))
			n, err = client.Read(readBuffer)
			if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
				fmt.Printf("Failed to read packet: %v\n", err)
				return
			} else if errors.Is(err, os.ErrDeadlineExceeded) {
				continue
			} else {
				if n != int(packetSize) {
					fmt.Printf("Packet is not completed, received bytes: %d\n", n)
					return
				}
				inOut.receivedPacket++
				break
			}
		}
	}
}

func prettyData(data float64) string {
	var (
		GB = 1024.0 * 1024.0 * 1024.0
		MB = 1024.0 * 1024.0
		KB = 1024.0
	)

	if data > GB {
		return fmt.Sprintf("%0.2f GB/s", data/GB)
	} else if data > MB {
		return fmt.Sprintf("%0.2f MB/s", data/MB)
	} else if data > KB {
		return fmt.Sprintf("%0.2f KB/s", data/KB)
	} else {
		return fmt.Sprintf("%0.2f B/s", data)
	}
}

func prettyReport(totalSent int, totalReceived int, packetSize uint64, duration time.Duration) {
	d := duration.Seconds()
	fmt.Printf("Sent: %0.2f req/s. Received: %0.2f req/s\n",
		float64(totalSent)/d, float64(totalReceived)/d)

	dataSentPerSec := float64(uint64(totalSent)*packetSize) / d
	dataReceivedPerSec := float64(uint64(totalReceived)*packetSize) / d

	fmt.Printf("DataSent: %s. Received: %s\n",
		prettyData(dataSentPerSec), prettyData(dataReceivedPerSec))
}

func clientAction(ctx *cli.Context) error {
	numClient := ctx.Int("client")
	packetSize := ctx.Uint64("packet.size")
	serverAddress := fmt.Sprintf("%s:%d", ctx.String("ip"), ctx.Int("port"))
	stop := make(chan struct{})

	var wg sync.WaitGroup

	inOut := make([]packetInOut, numClient)
	start := time.Now()
	for i := 0; i < numClient; i++ {
		wg.Add(1)
		go clientRoutine(serverAddress, packetSize, &wg, &inOut[i], stop)
	}

	time.Sleep(ctx.Duration("duration"))
	close(stop)
	wg.Wait()

	var totalSent, totalReceived int
	for i := 0; i < numClient; i++ {
		totalSent += inOut[i].sentPacket
		totalReceived += inOut[i].receivedPacket
	}
	duration := time.Since(start)
	prettyReport(totalSent, totalReceived, packetSize, duration)

	return nil
}

func main() {
	app := cli.App{
		Name: "echo client",
		Flags: []cli.Flag{
			&cli.IntFlag{
				Name:     "client",
				Usage:    "Number of TCP clients",
				Required: true,
			},
			&cli.Uint64Flag{
				Name:     "packet.size",
				Usage:    "Size of a packet",
				Required: true,
			},
			&cli.DurationFlag{
				Name:  "duration",
				Usage: "Benchmark duration",
				Value: 60 * time.Second,
			},
			&cli.StringFlag{
				Name:  "ip",
				Usage: "The server's IP address",
				Value: "127.0.0.1",
			},
			&cli.IntFlag{
				Name:  "port",
				Usage: "The server's port",
				Value: 8888,
			},
		},
		Action: clientAction,
	}

	if err := app.Run(os.Args); err != nil {
		panic(err)
	}
}
