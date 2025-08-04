package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
	"github.com/creack/pty"
)

const (
	apiBase         = "http://localhost:8081/api"
	hostKeyFilePath = "ssh_host_key"
	entrypointPath  = "entrypoint.sh"
)

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
type User struct {
	ID        int64  `json:"id"`
	Username  string `json:"username"`
	Role      string `json:"role"`
	AvatarURL string `json:"avatar_url"`
}

func apiLogin(username, password string) (*User, error) {
	creds := Credentials{Username: username, Password: password}
	body, _ := json.Marshal(creds)
	resp, err := http.Post(apiBase+"/login", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("API login error: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("invalid credentials")
	}
	var user User
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, fmt.Errorf("decode error: %w", err)
	}
	return &user, nil
}

func apiRegister(username, password string) error {
	creds := Credentials{Username: username, Password: password}
	body, _ := json.Marshal(creds)
	resp, err := http.Post(apiBase+"/register", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("API register error: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("registration failed: %s", string(b))
	}
	return nil
}

func loadHostKey(path string) (ssh.Signer, error) {
	keyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read SSH host key file: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SSH host key: %w", err)
	}
	return signer, nil
}

func main() {
	config := &ssh.ServerConfig{
		NoClientAuth: false,
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			log.Printf("PasswordCallback: conn.User()=%q, password=%q", conn.User(), string(password))
			failCount := 0
			for failCount < 3 {
				user, err := apiLogin(conn.User(), string(password))
				if err == nil {
					log.Printf("SSH login success for %s", user.Username)
					return &ssh.Permissions{
						Extensions: map[string]string{
							"username": conn.User(),
							"password": string(password),
						},
					}, nil
				}
				failCount++
				if failCount >= 3 {
					log.Printf("SSH login failed for %s after %d tries", conn.User(), failCount)
					return nil, fmt.Errorf("registration required")
				}
				return nil, fmt.Errorf("invalid credentials")
			}
			return nil, fmt.Errorf("registration required")
		},
	}

	signer, err := loadHostKey(hostKeyFilePath)
	if err != nil {
		log.Fatalf("Unable to load SSH host key: %v", err)
	}
	config.AddHostKey(signer)

	listener, err := net.Listen("tcp", ":2222")
	if err != nil {
		log.Fatal("failed to listen for connection: ", err)
	}
	log.Println("SSH server listening on :2222")

	for {
		nConn, err := listener.Accept()
		if err != nil {
			log.Println("Failed to accept incoming connection: ", err)
			continue
		}
		go handleSSHConn(nConn, config)
	}
}

func handleSSHConn(nConn net.Conn, config *ssh.ServerConfig) {
	sshConn, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		if strings.Contains(err.Error(), "registration required") {
			doRegistration(nConn)
			return
		}
		log.Printf("Failed handshake: %v", err)
		return
	}
	defer sshConn.Close()
	go ssh.DiscardRequests(reqs)
	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			log.Printf("could not accept channel: %v", err)
			continue
		}
		go handleSessionWithEntrypoint(channel, requests, sshConn.Permissions)
	}
}

func handleSessionWithEntrypoint(channel ssh.Channel, requests <-chan *ssh.Request, perms *ssh.Permissions) {
	hasPty := false
	var term string
	var winWidth, winHeight int
	for req := range requests {
		switch req.Type {
		case "shell":
			req.Reply(true, nil)
			runEntrypoint(channel, perms, hasPty, term, winWidth, winHeight)
			return
		case "pty-req":
			hasPty = true
			term, winWidth, winHeight = parsePtyReq(req.Payload)
			req.Reply(true, nil)
		case "window-change":
			winWidth, winHeight = parseWinChange(req.Payload)
			req.Reply(true, nil)
		default:
			req.Reply(false, nil)
		}
	}
}

func runEntrypoint(channel ssh.Channel, perms *ssh.Permissions, hasPty bool, term string, winWidth, winHeight int) {
	absEntrypoint, err := filepath.Abs(entrypointPath)
	if err != nil {
		fmt.Fprintf(channel, "Failed to resolve entrypoint path: %v\n", err)
		channel.Close()
		return
	}
	fi, err := os.Stat(absEntrypoint)
	if err != nil || fi.IsDir() {
		fmt.Fprintf(channel, "Entrypoint script not found or is a directory: %v\n", err)
		channel.Close()
		return
	}
	if err := isExecutable(absEntrypoint); err != nil {
		fmt.Fprintf(channel, "Entrypoint script is not executable: %v\n", err)
		channel.Close()
		return
	}
	cmd := exec.Command(absEntrypoint)
	env := os.Environ()
	// Log what is set in permissions
	if perms != nil {
		if user, ok := perms.Extensions["username"]; ok {
			log.Printf("runEntrypoint: USER=%q", user)
			env = append(env, "USER="+user)
		} else {
			log.Printf("runEntrypoint: USER not set")
		}
		if pass, ok := perms.Extensions["password"]; ok {
			log.Printf("runEntrypoint: PASS=%q", pass)
			env = append(env, "PASS="+pass)
		} else {
			log.Printf("runEntrypoint: PASS not set")
		}
	}
	cmd.Env = env // Ensure this is set for both PTY and non-PTY

	if hasPty {
		ptmx, err := pty.Start(cmd)
		if err != nil {
			fmt.Fprintf(channel, "Failed to start PTY: %v\n", err)
			channel.Close()
			return
		}
		defer func() { _ = ptmx.Close() }()
		pty.Setsize(ptmx, &pty.Winsize{Cols: uint16(winWidth), Rows: uint16(winHeight)})
		go func() { io.Copy(ptmx, channel) }()
		io.Copy(channel, ptmx)
	} else {
		cmd.Stdin = channel
		cmd.Stdout = channel
		cmd.Stderr = channel
		err = cmd.Run()
		if err != nil {
			fmt.Fprintf(channel, "Failed to run entrypoint: %v\n", err)
		}
	}
	channel.Close()
}

func isExecutable(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	mode := info.Mode()
	if mode&0111 == 0 {
		return fmt.Errorf("file is not executable")
	}
	return nil
}

// Parse PTY request payload for term and window size
func parsePtyReq(payload []byte) (term string, winWidth, winHeight int) {
	termLen := int(payload[3])
	term = string(payload[4 : 4+termLen])
	winWidth = int(uint32(payload[4+termLen])<<24 | uint32(payload[5+termLen])<<16 | uint32(payload[6+termLen])<<8 | uint32(payload[7+termLen]))
	winHeight = int(uint32(payload[8+termLen])<<24 | uint32(payload[9+termLen])<<16 | uint32(payload[10+termLen])<<8 | uint32(payload[11+termLen]))
	return
}

func parseWinChange(payload []byte) (winWidth, winHeight int) {
	winWidth = int(uint32(payload[0])<<24 | uint32(payload[1])<<16 | uint32(payload[2])<<8 | uint32(payload[3]))
	winHeight = int(uint32(payload[4])<<24 | uint32(payload[5])<<16 | uint32(payload[6])<<8 | uint32(payload[7]))
	return
}

func doRegistration(conn net.Conn) {
	config := &ssh.ServerConfig{
		NoClientAuth: true,
	}
	signer, err := loadHostKey(hostKeyFilePath)
	if err != nil {
		log.Printf("Unable to load SSH host key for registration: %v", err)
		return
	}
	config.AddHostKey(signer)

	sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		log.Printf("Failed registration handshake: %v", err)
		return
	}
	defer sshConn.Close()
	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			log.Printf("could not accept reg channel: %v", err)
			continue
		}
		go registrationShell(channel, requests)
	}
}

func registrationShell(channel ssh.Channel, requests <-chan *ssh.Request) {
	for req := range requests {
		switch req.Type {
		case "shell":
			req.Reply(true, nil)
			promptRegistration(channel)
			return
		case "pty-req":
			req.Reply(true, nil)
		default:
			req.Reply(false, nil)
		}
	}
	channel.Close()
}

func promptRegistration(channel ssh.Channel) {
	fmt.Fprintln(channel, "You have failed login too many times. Creating a new account.\n")
	var username, password string
	reader := channel

	for {
		fmt.Fprint(channel, "Enter new username: ")
		username, _ = readLineSSH(reader)
		if len(username) < 1 {
			fmt.Fprintln(channel, "Username too short.")
			continue
		}
		break
	}
	for {
		fmt.Fprint(channel, "Enter new password: ")
		password, _ = readLineSSH(reader)
		if len(password) < 4 {
			fmt.Fprintln(channel, "Password too short.")
			continue
		}
		break
	}

	if err := apiRegister(username, password); err == nil {
		fmt.Fprintf(channel, "User '%s' registered and logged in!\n", username)
		fmt.Fprintf(channel, "Welcome %s! You are now authenticated to the SSH server.\n", username)
	} else {
		fmt.Fprintf(channel, "Registration failed: %v\n", err)
	}
	channel.Close()
}

func readLineSSH(r io.Reader) (string, error) {
	var buf [256]byte
	n, err := r.Read(buf[:])
	if err != nil {
		return "", err
	}
	line := string(buf[:n])
	line = strings.TrimSpace(line)
	return line, nil
}