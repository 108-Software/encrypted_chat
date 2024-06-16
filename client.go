package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/quic-go/quic-go"
)

type AuthData struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func main() {
	hostName := flag.String("hostname", "192.168.0.100", "hostname/ip of the server") //подключаемся по адрессу
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

	fmt.Print("Enter your username: ") //запрашиваем имя пользователя и пароль
	usernameReader := bufio.NewReader(os.Stdin)
	username, _ := usernameReader.ReadString('\n')
	username = strings.TrimSpace(username)

	fmt.Print("Enter your password: ")
	passwordReader := bufio.NewReader(os.Stdin)
	password, _ := passwordReader.ReadString('\n')
	password = strings.TrimSpace(password)

	authData := AuthData{ // Формируем данные для аутентификации
		Username: username,
		Password: password,
	}

	authDataJSON, err := json.Marshal(authData) // Отправляем данные для аутентификации
	if err != nil {
		log.Fatal(err)
	}
	_, err = stream.Write(authDataJSON)
	if err != nil {
		log.Fatal(err)
	}

	go func(username string) {
		for {
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

			fmt.Printf("\r\033[K%s\x1b[34m *\x1b[0m\n", reply) //синяя звёздочка будет означать что сообщение пришло с сервера
			fmt.Print(username + ": ")
		}
	}(username)

	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print(username + ": ")
		message, err := reader.ReadString('\n')
		if err != nil {
			log.Println("Error reading message:", err)
			break
		}

		message = strings.TrimSpace(message)
		fullMessage := fmt.Sprintf("%s: %s", username, message)

		fmt.Printf("\033[1A\033[K%s\x1b[32m *\x1b[0m\n", fullMessage) // формирауем сообщение с зелёной звёздочкой что означает что сообщение доставлено

		_, err = stream.Write([]byte(message))
		if err != nil {
			log.Println("Error sending message:", err)
			break
		}
	}
}
