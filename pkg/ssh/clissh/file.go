// Copyright 2021 Flant JSC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package clissh

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	uuid "github.com/google/uuid"

	"github.com/deckhouse/lib-connection/pkg/settings"
	"github.com/deckhouse/lib-connection/pkg/ssh/clissh/cmd"
	"github.com/deckhouse/lib-connection/pkg/ssh/session"
)

type File struct {
	settings settings.Settings

	Session *session.Session
}

func NewFile(sett settings.Settings, sess *session.Session) *File {
	return &File{
		Session:  sess,
		settings: sett,
	}
}

func (f *File) Upload(ctx context.Context, srcPath, remotePath string) error {
	fType, err := CheckLocalPath(srcPath)
	if err != nil {
		return err
	}
	scp := cmd.NewSCP(f.settings, f.Session)
	scp.WithPreserve(true)
	if fType == "DIR" {
		scp.WithRecursive(true)
	}
	scp.WithSrc(srcPath).
		WithRemoteDst(remotePath).
		SCP(ctx).
		CaptureStdout(nil).
		CaptureStderr(nil)
	err = scp.Run(ctx)
	if err != nil {
		return fmt.Errorf(
			"upload file '%s': %w\n%s\nstderr: %s",
			srcPath,
			err,
			string(scp.StdoutBytes()),
			string(scp.StderrBytes()),
		)
	}

	return nil
}

// UploadBytes creates a tmp file and upload it to remote dstPath
func (f *File) UploadBytes(ctx context.Context, data []byte, remotePath string) error {
	logger := f.settings.Logger()
	srcPath, err := CreateEmptyTmpFile(f.settings)
	if err != nil {
		return fmt.Errorf("create source tmp file: %v", err)
	}
	defer func() {
		err := os.Remove(srcPath)
		if err != nil {
			logger.ErrorF("Error: cannot remove tmp file '%s': %v\n", srcPath, err)
		}
	}()

	err = os.WriteFile(srcPath, data, 0o600)
	if err != nil {
		return fmt.Errorf("write data to tmp file: %w", err)
	}

	scp := cmd.NewSCP(f.settings, f.Session).
		WithSrc(srcPath).
		WithRemoteDst(remotePath).
		SCP(ctx).
		CaptureStderr(nil).
		CaptureStdout(nil)
	err = scp.Run(ctx)
	if err != nil {
		return fmt.Errorf(
			"upload file '%s': %w\n%s\nstderr: %s",
			remotePath,
			err,
			string(scp.StdoutBytes()),
			string(scp.StderrBytes()),
		)
	}

	if len(scp.StdoutBytes()) > 0 {
		logger.InfoF("Upload file: %s", string(scp.StdoutBytes()))
	}
	return nil
}

func (f *File) Download(ctx context.Context, remotePath, dstPath string) error {
	logger := f.settings.Logger()

	scp := cmd.NewSCP(f.settings, f.Session)
	scp.WithRecursive(true)
	scpCmd := scp.WithRemoteSrc(remotePath).WithDst(dstPath).SCP(ctx)
	logger.DebugF("run scp: %s\n", scpCmd.Cmd().String())

	stdout, err := scpCmd.Cmd().CombinedOutput()
	if err != nil {
		return fmt.Errorf("download file '%s': %w", remotePath, err)
	}

	if len(stdout) > 0 {
		logger.InfoF("Download file: %s", string(stdout))
	}
	return nil
}

// Download remote file and returns its content as an array of bytes.
func (f *File) DownloadBytes(ctx context.Context, remotePath string) ([]byte, error) {
	logger := f.settings.Logger()

	dstPath, err := CreateEmptyTmpFile(f.settings)
	if err != nil {
		return nil, fmt.Errorf("create target tmp file: %v", err)
	}
	defer func() {
		err := os.Remove(dstPath)
		if err != nil {
			logger.InfoF("Error: cannot remove tmp file '%s': %v\n", dstPath, err)
		}
	}()

	scp := cmd.NewSCP(f.settings, f.Session)
	scpCmd := scp.WithRemoteSrc(remotePath).WithDst(dstPath).SCP(ctx)
	logger.DebugF("run scp: %s\n", scpCmd.Cmd().String())

	stdout, err := scpCmd.Cmd().CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("download file '%s': %w", remotePath, err)
	}

	if len(stdout) > 0 {
		logger.InfoF("Download file: %s", string(stdout))
	}

	data, err := os.ReadFile(dstPath)
	if err != nil {
		return nil, fmt.Errorf("reading tmp file '%s': %w", dstPath, err)
	}

	return data, nil
}

func CreateEmptyTmpFile(sett settings.Settings) (string, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return "", err
	}

	tmpPath := filepath.Join(
		sett.TmpDir(),
		fmt.Sprintf("dhctl-scp-%d-%s.tmp", os.Getpid(), id.String()),
	)

	file, err := os.OpenFile(tmpPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return "", err
	}

	_ = file.Close()
	return tmpPath, nil
}

// CheckLocalPath see if file exists and determine if it is a directory. Error is returned if file is not exists.
func CheckLocalPath(path string) (string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if fi.Mode().IsDir() {
		return "DIR", nil
	}
	if fi.Mode().IsRegular() {
		return "FILE", nil
	}
	return "", fmt.Errorf("Path '%s' is not a directory or file", path)
}
