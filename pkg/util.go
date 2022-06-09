package pkg

import (
	"fmt"
	"io/ioutil"
)

func ModifyFileContent(path string) error {

	return nil
}

func ProcessName(pid int32) (string, error) {
	contents, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	return string(contents), err
}
