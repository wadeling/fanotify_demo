package pkg

import (
	"fmt"
	"io/ioutil"
	"os/exec"
)

func ModifyFileContent(path string) error {
	cmd := exec.Command("./script/modify.sh", path)

	return cmd.Run()
}

func ProcessName(pid int32) (string, error) {
	contents, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	return string(contents), err
}
