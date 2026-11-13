package main

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type FTPServer struct {
	port      int
	rootDir   string
	username  string
	password  string
	listener  net.Listener
	mu        sync.Mutex
	isRunning bool
}

func NewFTPServer(port int, rootDir, username, password string) *FTPServer {
	return &FTPServer{
		port:     port,
		rootDir:  rootDir,
		username: username,
		password: password,
	}
}

func (s *FTPServer) Start() error {
	addr := fmt.Sprintf(":%d", s.port)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("FTP 監聽埠 %d 失敗: %w", s.port, err)
	}
	s.listener = l
	s.isRunning = true

	_ = os.MkdirAll(s.rootDir, 0755)
	fmt.Printf("[內建 FTP 服務] 🚀 已成功啟動！監聽 Port: %d | 目錄: %s | 帳號: %s\n", s.port, s.rootDir, s.username)

	go func() {
		for s.isRunning {
			conn, err := s.listener.Accept()
			if err != nil {
				if !s.isRunning {
					return
				}
				continue
			}
			go s.handleConn(conn)
		}
	}()
	return nil
}

func (s *FTPServer) handleConn(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	send := func(code int, msg string) {
		line := fmt.Sprintf("%d %s\r\n", code, msg)
		_, _ = writer.WriteString(line)
		_ = writer.Flush()
	}

	send(220, "PA-5250 High-Speed Log Receiver Go-FTP Ready")

	var user string
	var authenticated bool

	var dataListener net.Listener
	var dataConnChan chan net.Conn
	var activeAddr string

	closeDataListener := func() {
		if dataListener != nil {
			_ = dataListener.Close()
			dataListener = nil
		}
	}
	defer closeDataListener()

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		cmdLine := strings.TrimSpace(line)
		if cmdLine == "" {
			continue
		}

		parts := strings.SplitN(cmdLine, " ", 2)
		verb := strings.ToUpper(parts[0])
		arg := ""
		if len(parts) > 1 {
			arg = strings.TrimSpace(parts[1])
		}

		switch verb {
		case "USER":
			user = arg
			send(331, "User name okay, need password.")

		case "PASS":
			if (s.username == "" || user == s.username) && (s.password == "" || arg == s.password) {
				authenticated = true
				send(230, "User logged in, proceed.")
			} else {
				send(530, "Login incorrect.")
				return
			}

		case "SYST":
			send(215, "UNIX Type: L8")

		case "FEAT":
			feat := "211-Features:\r\n PASV\r\n EPSV\r\n TYPE I\r\n UTF8\r\n211 End\r\n"
			_, _ = writer.WriteString(feat)
			_ = writer.Flush()

		case "PWD":
			send(257, `"/" is current directory.`)

		case "CWD", "CDUP":
			send(250, "Directory changed successfully.")

		case "TYPE":
			send(200, "Type set to "+arg)

		case "OPTS":
			send(200, "OPTS command successful.")

		case "NOOP":
			send(200, "NOOP OK.")

		case "PASV":
			if !authenticated {
				send(530, "Please login first.")
				continue
			}
			closeDataListener()

			dl, err := net.Listen("tcp", ":0")
			if err != nil {
				send(425, "Cannot open passive data connection.")
				continue
			}
			dataListener = dl
			dataConnChan = make(chan net.Conn, 1)

			go func(l net.Listener, ch chan net.Conn) {
				c, err := l.Accept()
				if err == nil {
					ch <- c
				}
			}(dl, dataConnChan)

			pasvPort := dl.Addr().(*net.TCPAddr).Port
			p1 := pasvPort / 256
			p2 := pasvPort % 256

			localIP := conn.LocalAddr().(*net.TCPAddr).IP.To4()
			if localIP == nil {
				localIP = net.ParseIP("127.0.0.1").To4()
			}

			pasvMsg := fmt.Sprintf("Entering Passive Mode (%d,%d,%d,%d,%d,%d).",
				localIP[0], localIP[1], localIP[2], localIP[3], p1, p2)
			send(227, pasvMsg)

		case "EPSV":
			if !authenticated {
				send(530, "Please login first.")
				continue
			}
			closeDataListener()
			dl, err := net.Listen("tcp", ":0")
			if err != nil {
				send(425, "Cannot open passive data connection.")
				continue
			}
			dataListener = dl
			dataConnChan = make(chan net.Conn, 1)

			go func(l net.Listener, ch chan net.Conn) {
				c, err := l.Accept()
				if err == nil {
					ch <- c
				}
			}(dl, dataConnChan)

			pasvPort := dl.Addr().(*net.TCPAddr).Port
			send(229, fmt.Sprintf("Entering Extended Passive Mode (|||%d|).", pasvPort))

		case "PORT":
			if !authenticated {
				send(530, "Please login first.")
				continue
			}
			closeDataListener()
			nums := strings.Split(arg, ",")
			if len(nums) == 6 {
				ip := strings.Join(nums[0:4], ".")
				p1, _ := strconv.Atoi(nums[4])
				p2, _ := strconv.Atoi(nums[5])
				activeAddr = fmt.Sprintf("%s:%d", ip, p1*256+p2)
				send(200, "PORT command successful.")
			} else {
				send(501, "Syntax error in parameters.")
			}

		case "STOR":
			if !authenticated {
				send(530, "Please login first.")
				continue
			}

			var dataConn net.Conn
			if dataListener != nil {
				send(150, "Opening BINARY mode data connection for "+arg)
				select {
				case c := <-dataConnChan:
					dataConn = c
				case <-time.After(15 * time.Second):
					send(425, "Data connection timed out.")
					closeDataListener()
					continue
				}
				closeDataListener()
			} else if activeAddr != "" {
				send(150, "Opening BINARY mode data connection for "+arg)
				c, err := net.DialTimeout("tcp", activeAddr, 10*time.Second)
				if err != nil {
					send(425, "Cannot connect to active client port.")
					continue
				}
				dataConn = c
				activeAddr = ""
			} else {
				send(425, "Use PASV or PORT first.")
				continue
			}

			// 🌟 方案 A 關鍵：即時檢測 CSV 並轉為 .csv.gz 串流壓縮落盤
			fileName := filepath.Base(arg)
			isCSV := strings.HasSuffix(strings.ToLower(fileName), ".csv")
			if isCSV && !strings.HasSuffix(strings.ToLower(fileName), ".gz") {
				fileName += ".gz"
			}

			filePath := filepath.Join(s.rootDir, fileName)
			outFile, err := os.Create(filePath)
			if err != nil {
				dataConn.Close()
				send(550, "Create file failed: "+err.Error())
				continue
			}

			var copyErr error
			if isCSV {
				// 啟用 Gzip BestSpeed (Level 1)：吞吐量突破 250MB/s，CPU 消耗低，大幅壓制磁碟 I/O
				gw, _ := gzip.NewWriterLevel(outFile, gzip.BestSpeed)
				bufWriter := bufio.NewWriterSize(gw, 1*1024*1024)
				_, copyErr = io.Copy(bufWriter, dataConn)
				_ = bufWriter.Flush()
				_ = gw.Close()
			} else {
				bufWriter := bufio.NewWriterSize(outFile, 1*1024*1024)
				_, copyErr = io.Copy(bufWriter, dataConn)
				_ = bufWriter.Flush()
			}
			_ = outFile.Close()
			_ = dataConn.Close()

			if copyErr != nil {
				send(426, "Connection closed; transfer aborted.")
			} else {
				send(226, "Transfer complete.")
			}

		case "QUIT":
			send(221, "Goodbye.")
			return

		default:
			send(200, "Command OK.")
		}
	}
}

func (s *FTPServer) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.isRunning = false
	if s.listener != nil {
		_ = s.listener.Close()
	}
}