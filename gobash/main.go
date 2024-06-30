package main
import (
	"log"
	"os"
	"os/exec"
)
func main() {
	busybox := "busybox"
	args := []string{"ash"}
	cmd := exec.Command(busybox, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("execv error: %v", err)
	}
}
