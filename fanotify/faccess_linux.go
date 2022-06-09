package fanotify

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	"os"
	"sync"
)

const procSelfFd = "/proc/self/fd/%d"
const procRootMountPoint = "/proc/%d/root"

type faProcGrpRef struct {
	name string // parent name
	path string // parent path
	ppid int
}

// whitelist per container
type rootFd struct {
	pid            int
	id             string
	setting        string
	group          string
	whlst          map[string]int // not set: -1, deny: 0, allow: 1, ....
	dirMonitorList []string
	allowProcList  []faProcGrpRef        // allowed process group
	permitProcGrps map[int]*faProcGrpRef // permitted pgid and ppid
}

type FileAccessCtrl struct {
	bEnabled bool
	//prober        *Probe
	ctrlMux       sync.Mutex
	fanfd         *NotifyFD
	roots         map[string]*rootFd // container id, invidual control list
	lastReportPid int                // filtering reppeated report
	marks         int                // monitor total aloocated marks
	cflag         uint64             // fanotify configuration flags( open-perm or exec-perm)
}

func NewFileAccessCtrl() (*FileAccessCtrl, bool) {
	log.Debug("new file access ctrl")
	fa := &FileAccessCtrl{
		bEnabled: false,
		roots:    make(map[string]*rootFd),
	}

	// docker cp (file changes) might change the polling behaviors,
	// remove the non-block io to controller the polling timeouts
	flags := FAN_CLASS_CONTENT | FAN_UNLIMITED_MARKS | FAN_UNLIMITED_QUEUE | FAN_NONBLOCK
	fn, err := Initialize(flags, unix.O_RDONLY|unix.O_LARGEFILE)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("FA: Initialize")
		return nil, false
	}

	// fill in
	fa.bEnabled = true
	fa.fanfd = fn
	log.WithFields(log.Fields{"faFd": *fn}).Debug("fa info")

	// default: test the availability of open_permissions
	if !fa.isSupportOpenPerm() {
		fa.bEnabled = false // reset it back
		return nil, false
	}
	fa.cflag = FAN_OPEN_PERM

	// preferable flag
	if fa.isSupportExecPerm() {
		log.Info("FA: ExecPerm is supported")
		fa.cflag = fa.cflag | FAN_OPEN_EXEC_PERM
	}

	// add monitor dir
	fa.addDirMarks(os.Getpid(), []string{"/root/go"})

	go fa.monitorFilePermissionEvents()
	return fa, true
}

func (fa *FileAccessCtrl) isSupportOpenPerm() bool {
	//path := fmt.Sprintf(procRootMountPoint, 1) // when in container,use pid 1
	path := fmt.Sprintf(procRootMountPoint, os.Getpid())
	err := fa.fanfd.Mark(FAN_MARK_ADD, FAN_OPEN_PERM, unix.AT_FDCWD, path)
	_ = fa.fanfd.Mark(FAN_MARK_REMOVE, FAN_OPEN_PERM, unix.AT_FDCWD, path)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Debug("FA: FAN_OPEN_PERM not supported")
		return false
	}
	return true
}

func (fa *FileAccessCtrl) isSupportExecPerm() bool {
	//path := fmt.Sprintf(procRootMountPoint, 1)
	path := fmt.Sprintf(procRootMountPoint, os.Getpid())
	err := fa.fanfd.Mark(FAN_MARK_ADD, FAN_OPEN_EXEC_PERM, unix.AT_FDCWD, path)
	_ = fa.fanfd.Mark(FAN_MARK_REMOVE, FAN_OPEN_EXEC_PERM, unix.AT_FDCWD, path)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Debug("FA: FAN_OPEN_EXEC_PERM not supported")
		return false
	}
	return true
}

func (fa *FileAccessCtrl) monitorFilePermissionEvents() {
	waitCnt := 0
	pfd := make([]unix.PollFd, 1)
	pfd[0].Fd = fa.fanfd.GetFd()
	pfd[0].Events = unix.POLLIN
	log.WithFields(log.Fields{"pfd": pfd[0]}).Info("FA: start")
	for {
		n, err := unix.Poll(pfd, 5000) // wait 1 sec
		log.Debugf("poll get event:%d", n)
		if err != nil && err != unix.EINTR { // not interrupted by a signal
			log.WithFields(log.Fields{"err": err}).Error("FA: poll returns error")
			break
		}

		if n <= 0 {
			if n == 0 && !fa.bEnabled { // timeout at exit stage
				waitCnt += 1
				if waitCnt > 1 { // two chances
					break
				}
			}
			continue
		}

		log.Debugf("poll event:%+v", pfd[0])
		if (pfd[0].Revents & unix.POLLIN) != 0 {
			fa.handleEvents()
			waitCnt = 0
		}
	}

	fa.monitorExit()
	log.Info("FA: exit")
}

func (fa *FileAccessCtrl) handleEvents() {
	for fa.bEnabled {
		ev, err := fa.fanfd.GetEvent()
		if err != nil {
			log.WithFields(log.Fields{"err": err}).Error("handle event err")
			return
		}
		log.WithFields(log.Fields{"event": *ev}).Debug("event info")

		if ev.Version == FANOTIFY_METADATA_VERSION {
			fa.lockMux()
			err := fa.fanfd.Response(ev, false)
			if err != nil {
				log.WithFields(log.Fields{"err": err}).Error("response allow err")
			} else {
				log.Debug("response allow ok")
			}
			fa.unlockMux()
		} else {
			log.WithFields(log.Fields{"ev": ev}).Error("FA: wrong metadata version")
		}
		err = ev.File.Close()
		if err != nil {
			log.WithFields(log.Fields{"err": err}).Error("ev file close err.")
		}
	}
}

func (fa *FileAccessCtrl) lockMux() {
	// log.WithFields(log.Fields{"goroutine": utils.GetGID()}).Debug("FA: ")
	fa.ctrlMux.Lock()
}

func (fa *FileAccessCtrl) unlockMux() {
	fa.ctrlMux.Unlock()
	// log.WithFields(log.Fields{"goroutine": utils.GetGID()}).Debug("FA: ")
}

func (fa *FileAccessCtrl) monitorExit() {
	if fa.fanfd != nil {
		fa.fanfd.Close()
	}

	//if fa.prober != nil {
	//	fa.prober.FaEndChan <- true
	//}
}

func (fa *FileAccessCtrl) addDirMarks(pid int, dirs []string) (bool, int) {
	log.WithFields(log.Fields{"pid": pid, "dirs": dirs}).Debug("FA: add dir marks start")

	ppath := fmt.Sprintf(procRootMountPoint, pid)
	for _, dir := range dirs {
		path := ppath + dir
		err := fa.fanfd.Mark(FAN_MARK_ADD, fa.cflag|FAN_EVENT_ON_CHILD, unix.AT_FDCWD, path)
		if err != nil {
			log.WithFields(log.Fields{"path": path, "error": err}).Error("FA: add mark failed")
		} else {
			log.WithFields(log.Fields{"path": path}).Debug("FA: add mark ok")
		}
	}
	return true, len(dirs)
}
