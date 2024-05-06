package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"io"
	"log"
	"math/big"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

func main() {
	hostName := flag.String("hostname", "192.168.0.100", "hostname/ip of the server")
	portNum := flag.String("port", "4242", "port number of the server")

	flag.Parse()

	addr := *hostName + ":" + *portNum

	log.Println("Server running @", addr)

	listener, err := quic.ListenAddr(addr, generateTLSConfig(), nil)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	messageCh := make(chan []byte)
	senderCh := make(chan quic.Stream)

	go broadcastMessages(messageCh, senderCh)

	for {
		sess, err := listener.Accept(context.Background())
		if err != nil {
			log.Println(err)
			continue
		}

		go handleSession(sess, messageCh, senderCh)
	}
}

func handleSession(sess quic.Connection, messageCh chan<- []byte, senderCh chan<- quic.Stream) {
	defer sess.CloseWithError(0, "")
	defer log.Println("Session closed")

	log.Println("Session opened")

	stream, err := sess.AcceptStream(context.Background())
	if err != nil {
		log.Println(err)
		return
	}
	defer stream.Close()

	log.Println("Stream opened")

	clientMu.Lock()
	clients[stream] = struct{}{}
	clientMu.Unlock()

	for {
		buf := make([]byte, 1024)
		n, err := stream.Read(buf)
		if err != nil {
			if err == io.EOF {
				log.Println("Client disconnected")
				return
			}
			log.Println(err)
			return
		}

		message := buf[:n]
		log.Printf("Received message: %s\n", message)

		messageCh <- message
		senderCh <- stream
	}
}

func broadcastMessages(messageCh <-chan []byte, senderCh <-chan quic.Stream) {
	for {
		select {
		case message := <-messageCh:
			sender := <-senderCh
			clientMu.Lock()
			for client := range clients {
				if client != sender {
					if _, err := client.Write(message); err != nil {
						log.Println("Error writing message to client:", err)
					}
				}
			}
			clientMu.Unlock()
		}
	}
}

var (
	clients  = make(map[quic.Stream]struct{})
	clientMu sync.Mutex
)

func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		log.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		log.Fatal(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"quic-echo"},
	}
}
