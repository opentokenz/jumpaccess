package terminalprompt

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/cmstar/jumpaccess/internal/jumpserver"
	"golang.org/x/term"
)

func SelectAccount(input io.Reader, output io.Writer, accounts []jumpserver.Account) (jumpserver.Account, error) {
	if len(accounts) == 0 {
		return jumpserver.Account{}, fmt.Errorf("no permitted accounts")
	}
	if _, err := fmt.Fprintln(output, "Select a permitted account:"); err != nil {
		return jumpserver.Account{}, err
	}
	for index, account := range accounts {
		identity := account.Username
		if identity == "" {
			identity = account.Name
		}
		if identity == "" {
			identity = account.ID
		}
		if _, err := fmt.Fprintf(output, "%d) %s", index+1, identity); err != nil {
			return jumpserver.Account{}, err
		}
		if account.Name != "" && account.Name != identity {
			if _, err := fmt.Fprintf(output, " (%s)", account.Name); err != nil {
				return jumpserver.Account{}, err
			}
		}
		if _, err := fmt.Fprintln(output); err != nil {
			return jumpserver.Account{}, err
		}
	}
	if _, err := fmt.Fprint(output, "Account number: "); err != nil {
		return jumpserver.Account{}, err
	}
	line, err := readLine(input)
	if err != nil {
		return jumpserver.Account{}, fmt.Errorf("read account selection: %w", err)
	}
	selected, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil || selected < 1 || selected > len(accounts) {
		return jumpserver.Account{}, fmt.Errorf("invalid account selection")
	}
	return accounts[selected-1], nil
}

func ConfirmHostKey(input io.Reader, output io.Writer, host, fingerprint string) (bool, error) {
	if _, err := fmt.Fprintf(output, "Unknown SSH host key for %s\nFingerprint: %s\nTrust this host key? [y/N]: ", host, fingerprint); err != nil {
		return false, err
	}
	line, err := readLine(input)
	if err != nil {
		return false, fmt.Errorf("read host key confirmation: %w", err)
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true, nil
	default:
		return false, nil
	}
}

func readLine(input io.Reader) (string, error) {
	var result strings.Builder
	buffer := []byte{0}
	for result.Len() < 1024 {
		read, err := input.Read(buffer)
		if read > 0 {
			if buffer[0] == '\n' {
				return strings.TrimSuffix(result.String(), "\r"), nil
			}
			result.WriteByte(buffer[0])
		}
		if err != nil {
			if err == io.EOF && result.Len() > 0 {
				return result.String(), nil
			}
			return "", err
		}
	}
	return "", fmt.Errorf("input line is too long")
}

// ReadSecret 从终端隐藏读取一次性输入，用于粘贴 Cookie 等凭据。
// 非终端输入直接拒绝，避免凭据被回显或留在管道中。
func ReadSecret(input *os.File, output io.Writer, prompt string) (string, error) {
	if input == nil {
		return "", fmt.Errorf("standard input is unavailable")
	}
	fd := int(input.Fd())
	if !term.IsTerminal(fd) {
		return "", fmt.Errorf("standard input is not a terminal; cannot read the cookie without echo protection")
	}
	if _, err := fmt.Fprint(output, prompt); err != nil {
		return "", err
	}
	data, err := term.ReadPassword(fd)
	if _, writeErr := fmt.Fprintln(output); writeErr != nil && err == nil {
		err = writeErr
	}
	if err != nil {
		return "", fmt.Errorf("read hidden input: %w", err)
	}
	value := strings.TrimSpace(string(data))
	clear(data)
	if value == "" {
		return "", fmt.Errorf("input is empty")
	}
	return value, nil
}
