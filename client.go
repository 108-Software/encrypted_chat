package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"flag"
	"io"
	"log"
	"os"
	"time"

	"github.com/quic-go/quic-go"
)

func main() {
	hostName := flag.String("hostname", "192.168.0.100", "hostname/ip of the server")
	portNum := flag.String("port", "4242", "port number of the server")

	flag.Parse()

	addr := *hostName + ":" + *portNum

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"quic-echo"},
	}

	session, err := quic.DialAddr(context.Background(), addr, tlsConf, nil)
	if err != nil {
		log.Fatal(err)
	}

	stream, err := session.OpenStreamSync(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	reader := bufio.NewReader(os.Stdin)
	for {
		message, err := reader.ReadString('\n')
		if err != nil {
			log.Println("Error reading message:", err)
			break
		}

		log.Printf("Client: Sending %s", message)
		_, err = stream.Write([]byte(message))
		if err != nil {
			log.Println("Error sending message:", err)
			break
		}

		log.Println("Done. Waiting for echo")

		// Ожидаем ответ от сервера
		buff := make([]byte, 1024)
		n, err := stream.Read(buff)
		if err != nil {
			if err == io.EOF {
				log.Println("Server disconnected")
				break
			}
			log.Println("Error reading response:", err)
			break
		}

		reply := string(buff[:n])
		log.Printf("Client: Got %s", reply)

		// Пауза перед отправкой следующего сообщения
		time.Sleep(100 * time.Millisecond)
	}
}
