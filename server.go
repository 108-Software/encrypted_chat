package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"strings"
	"sync"
	"time"

	"example.com/m/database"
	"github.com/quic-go/quic-go"
)

type AuthData struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Client struct {
	Username string
	Stream   quic.Stream
}

var (
	clients  = make(map[quic.Stream]*Client)
	clientMu sync.Mutex
)

func main() {
	hostName := flag.String("hostname", "192.168.0.100", "hostname/ip of the server") //указываем удресс и порт для сервера
	portNum := flag.String("port", "4242", "port number of the server")

	flag.Parse()

	addr := *hostName + ":" + *portNum

	log.Println("Server running @", addr)

	listener, err := quic.ListenAddr(addr, generateTLSConfig(), &quic.Config{}) //запускаем и слушаем по адресу, сервер
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	messageCh := make(chan []byte)
	senderCh := make(chan quic.Stream)

	go broadcastMessages(messageCh, senderCh) //обрабатываем входящии сообщения

	for {
		sess, err := listener.Accept(context.Background())
		if err != nil {
			log.Println(err)
			continue
		}

		go handleSession(sess, messageCh, senderCh)
	}
}

func handleSession(sess quic.Connection, messageCh chan<- []byte, senderCh chan<- quic.Stream) { //организовываем отдельную сессию для каждого клиента
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

	// Authentication
	buf := make([]byte, 1024) //принимаем данные для аутентификации пользователей
	n, err := stream.Read(buf)
	if err != nil {
		log.Println("Error reading authentication data:", err)
		return
	}

	var authData AuthData
	err = json.Unmarshal(buf[:n], &authData)
	if err != nil {
		log.Println("Error unmarshalling authentication data:", err)
		return
	}

	loginData := map[string]interface{}{
		"username": authData.Username,
		"password": authData.Password,
	}

	if !database.Search_account_map(loginData) { //ищем учётную запись в бд
		log.Println("Authentication failed for user:", authData.Username)
		return
	}

	log.Println("User authenticated:", authData.Username)

	clientMu.Lock()
	clients[stream] = &Client{
		Username: authData.Username,
		Stream:   stream,
	}
	clientMu.Unlock()

	for {
		n, err := stream.Read(buf)
		if err != nil {
			if err == io.EOF {
				log.Println("Client disconnected")
				clientMu.Lock()
				delete(clients, stream)
				clientMu.Unlock()
				return
			}
			log.Println(err)
			return
		}

		message := buf[:n]
		log.Printf("Received message: %s\n", message)

		handleMessage(authData.Username, message, messageCh, senderCh, stream)
	}
}

func handleMessage(username string, message []byte, messageCh chan<- []byte, senderCh chan<- quic.Stream, sender quic.Stream) { //принимаем и ищем кому отправить личные сообщение между клиентами
	messageStr := string(message)
	if strings.HasPrefix(messageStr, "/msg ") {
		parts := strings.SplitN(messageStr, " ", 3)
		if len(parts) < 3 {
			return
		}
		targetUsername := parts[1]
		privateMessage := fmt.Sprintf("[Private] %s: %s", username, parts[2])
		sendPrivateMessage(targetUsername, privateMessage)
	} else {
		formattedMessage := fmt.Sprintf("%s: %s", username, messageStr)
		messageCh <- []byte(formattedMessage)
		senderCh <- sender
	}
}

func sendPrivateMessage(targetUsername, message string) { // отправка приватных сообщений
	clientMu.Lock()
	defer clientMu.Unlock()
	for _, client := range clients {
		if client.Username == targetUsername {
			if _, err := client.Stream.Write([]byte(message)); err != nil {
				log.Println("Error writing private message to client:", err)
			}
			return
		}
	}
}

func broadcastMessages(messageCh <-chan []byte, senderCh <-chan quic.Stream) { //рассылаем публичные сообщения всем клиентам на сервере
	for {
		select {
		case message := <-messageCh:
			sender := <-senderCh
			clientMu.Lock()
			for clientStream, client := range clients {
				if clientStream != sender {
					if _, err := client.Stream.Write(message); err != nil {
						log.Println("Error writing message to client:", err)
					}
				}
			}
			clientMu.Unlock()
		}
	}
}

func generateTLSConfig() *tls.Config { //установка конфигурации сервера
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
