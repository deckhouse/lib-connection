// Copyright 2025 Flant JSC
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

package gossh

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"testing"

	"github.com/deckhouse/lib-connection/pkg/settings"
	"github.com/stretchr/testify/require"

	sshtesting "github.com/deckhouse/lib-connection/pkg/ssh/gossh/testing"
)

func TestSSHFileUpload(t *testing.T) {
	test := sshtesting.ShouldNewTest(t, "TestCommandOutput")

	const uploadDir = "upload_dir"
	const testFileContent = "Hello World"
	const notExec = false

	filePath := func(subPath ...string) []string {
		require.NotEmpty(t, subPath, "subPath is empty for filePath")
		return append([]string{uploadDir}, subPath...)
	}

	testFile := test.MustCreateTmpFile(t, testFileContent, notExec, filePath("upload")...)
	testDir := filepath.Dir(testFile)
	test.MustCreateTmpFile(t, "second", notExec, filePath("second")...)
	test.MustCreateTmpFile(t, "empty", notExec, filePath("second")...)
	test.MustCreateTmpFile(t, "sub", notExec, filePath("sub", "third")...)

	symlink := filepath.Join(test.LocalTmpDir, "symlink")
	err := os.Symlink(testFile, symlink)
	require.NoError(t, err)

	sshClient := startContainerAndClient(t, test)

	t.Run("Upload files and directories to container via existing ssh client", func(t *testing.T) {
		cases := []struct {
			title   string
			srcPath string
			dstPath string
			wantErr bool
			err     string
		}{
			{
				title:   "Single file",
				srcPath: testFile,
				dstPath: ".",
				wantErr: false,
			},
			{
				title:   "Directory",
				srcPath: testDir,
				dstPath: "/tmp",
				wantErr: false,
			},
			{
				title:   "Nonexistent",
				srcPath: "/path/to/nonexistent/flie",
				dstPath: "/tmp",
				wantErr: true,
				err:     "failed to open local file",
			},
			{
				title:   "File to root",
				srcPath: testFile,
				dstPath: "/any",
				wantErr: true,
			},
			{
				title:   "File to /var/lib",
				srcPath: testFile,
				dstPath: "/var/lib",
				wantErr: true,
			},
			{
				title:   "File to unaccessible file",
				srcPath: testFile,
				dstPath: "/path/what/not/exists.txt",
				wantErr: true,
				err:     "failed to copy file to remote host",
			},
			{
				title:   "Directory to root",
				srcPath: testDir,
				dstPath: "/",
				wantErr: true,
			},
			{
				title:   "Symlink",
				srcPath: symlink,
				dstPath: ".",
				wantErr: false,
			},
			{
				title:   "Device",
				srcPath: "/dev/zero",
				dstPath: "/",
				wantErr: true,
				err:     "is not a directory or file",
			},
			{
				title:   "Unaccessible dir",
				srcPath: "/var/audit",
				dstPath: ".",
				wantErr: true,
				err:     "could not read directory",
			},
			{
				title:   "Unaccessible file",
				srcPath: "/etc/sudoers",
				dstPath: ".",
				wantErr: true,
				err:     "failed to open local file",
			},
		}

		for _, c := range cases {
			t.Run(c.title, func(t *testing.T) {
				f := sshClient.File()
				err = f.Upload(context.Background(), c.srcPath, c.dstPath)
				if !c.wantErr {
					require.NoError(t, err)
				} else {
					require.Error(t, err)
					require.Contains(t, err.Error(), c.err)
				}
			})
		}
	})

	t.Run("Equality of uploaded and local file content", func(t *testing.T) {
		f := sshClient.File()
		err := f.Upload(context.Background(), testFile, "/tmp/testfile.txt")
		// testFile contains "Hello world" string
		require.NoError(t, err)

		assertFilesViaRemoteRun(t, sshClient, "cat /tmp/testfile.txt", testFileContent)
	})

	t.Run("Equality of uploaded and local directory", func(t *testing.T) {
		f := sshClient.File()
		err := f.Upload(context.Background(), testDir, "/tmp/upload")
		require.NoError(t, err)

		cmd := exec.Command("ls", testDir)
		lsResult, err := cmd.Output()
		require.NoError(t, err)

		assertFilesViaRemoteRun(t, sshClient, "ls /tmp/upload", string(lsResult))
	})
}

func TestSSHFileUploadBytes(t *testing.T) {
	test := sshtesting.ShouldNewTest(t, "TestSSHFileUploadBytes")

	sshClient := startContainerAndClient(t, test)

	t.Run("Upload bytes", func(t *testing.T) {
		const content = "Hello world"
		f := sshClient.File()
		err := f.UploadBytes(context.Background(), []byte(content), "/tmp/testfile.txt")
		require.NoError(t, err)

		assertFilesViaRemoteRun(t, sshClient, "cat /tmp/testfile.txt", content)
	})
}

func TestCreateEmptyTmpFile(t *testing.T) {
	sshtesting.CheckSkipSSHTest(t, "TestCreateEmptyTmpFile")

	t.Run("Creating empty temp file", func(t *testing.T) {
		cases := []struct {
			title      string
			tmpDirName string
			wantErr    bool
			err        string
		}{
			{
				title:      "Accessible tmp",
				tmpDirName: os.TempDir(),
				wantErr:    false,
			},
			{
				title:      "Unaccessible tmp",
				tmpDirName: "/var/lib",
				wantErr:    true,
				err:        "permission denied",
			},
		}

		for _, c := range cases {
			t.Run(c.title, func(t *testing.T) {
				uid := os.Geteuid()
				sshSettings := settings.NewBaseProviders(settings.ProviderParams{
					TmpDir: c.tmpDirName,
				})
				if uid == 0 && c.wantErr {
					t.Skip("Test TestCreateEmptyTmpFile was skipped, cannot try to access unaccessible dir from root user")
				}
				filename, err := CreateEmptyTmpFile(sshSettings)
				if !c.wantErr {
					require.NoError(t, err)
					os.Remove(filename)
				} else {
					require.Error(t, err)
					require.Contains(t, err.Error(), c.err)
				}
			})
		}
	})
}

func TestSSHFileDownload(t *testing.T) {
	test := sshtesting.ShouldNewTest(t, "TestSSHFileDownload")

	sshClient := startContainerAndClient(t, test)

	const expectedFileContent = "Some test data"

	// preparing some test related data
	err := sshClient.Command("mkdir  -p /tmp/testdata").Run(context.Background())
	require.NoError(t, err)
	err = sshClient.Command(fmt.Sprintf(`echo -n '%s' > /tmp/testdata/first`, expectedFileContent)).Run(context.Background())
	require.NoError(t, err)
	err = sshClient.Command("touch /tmp/testdata/second").Run(context.Background())
	require.NoError(t, err)
	err = sshClient.Command("touch /tmp/testdata/third").Run(context.Background())
	require.NoError(t, err)
	err = sshClient.Command("ln -s /tmp/testdata/first /tmp/link").Run(context.Background())
	require.NoError(t, err)

	t.Run("Download files and directories to container via existing ssh client", func(t *testing.T) {
		testDir := test.MustMkSubDirs(t, "download")

		cases := []struct {
			title   string
			srcPath string
			dstPath string
			wantErr bool
			err     string
		}{
			{
				title:   "Single file",
				srcPath: "/tmp/testdata/first",
				dstPath: testDir,
				wantErr: false,
			},
			{
				title:   "Directory",
				srcPath: "/tmp/testdata",
				dstPath: path.Join(testDir, "downloaded"),
				wantErr: false,
			},
			{
				title:   "Nonexistent",
				srcPath: "/path/to/nonexistent/flie",
				dstPath: "/tmp",
				wantErr: true,
			},
			{
				title:   "File to root",
				srcPath: "/tmp/testdata/first",
				dstPath: "/any",
				wantErr: true,
			},
			{
				title:   "File to /var/lib",
				srcPath: "/tmp/testdata/first",
				dstPath: "/var/lib",
				wantErr: true,
			},
			{
				title:   "File to unaccessible file",
				srcPath: "/tmp/testdata/first",
				dstPath: "/path/what/not/exists.txt",
				wantErr: true,
				err:     "no such file or directory",
			},
			{
				title:   "Directory to root",
				srcPath: "/tmp/testdata",
				dstPath: "/",
				wantErr: true,
			},
			{
				title:   "Symlink",
				srcPath: "/tmp/link",
				dstPath: testDir,
				wantErr: false,
			},
			{
				title:   "Device",
				srcPath: "/dev/zero",
				dstPath: "/",
				wantErr: true,
				err:     "failed to open local file",
			},
			{
				title:   "Unaccessible dir",
				srcPath: "/var/audit",
				dstPath: testDir,
				wantErr: true,
			},
			{
				title:   "Unaccessible file",
				srcPath: "/etc/sudoers",
				dstPath: testDir,
				wantErr: true,
				err:     "failed to copy file from remote host",
			},
		}

		for _, c := range cases {
			t.Run(c.title, func(t *testing.T) {
				f := sshClient.File()
				err := f.Download(context.Background(), c.srcPath, c.dstPath)
				if c.wantErr {
					require.Error(t, err)
					require.Contains(t, err.Error(), c.err)
					return
				}

				require.NoError(t, err)

				_, err = os.Stat(c.dstPath)
				require.NoError(t, err, "%s path should exist after download", c.dstPath)
			})
		}
	})

	t.Run("Equality of downloaded and remote file content", func(t *testing.T) {
		downloadContentDir := test.MustMkSubDirs(t, "download_content")

		f := sshClient.File()

		dstPath := path.Join(downloadContentDir, "testfile.txt")

		err := f.Download(context.Background(), "/tmp/testdata/first", dstPath)
		// /tmp/testdata/first contains "Some test data" string
		require.NoError(t, err)

		assertFilesViaRemoteRun(t, sshClient, "cat /tmp/testdata/first", dstPath)

		downloadedContent, err := os.ReadFile(dstPath)
		require.NoError(t, err)
		// out contains a contant of uploaded file, should be equal to testFile contant
		require.Equal(t, expectedFileContent, string(downloadedContent))
	})

	t.Run("Equality of downloaded and remote directory", func(t *testing.T) {
		downloadWholeDirDir := test.MustMkSubDirs(t, "download_dir")

		f := sshClient.File()
		err = f.Download(context.Background(), "/tmp/testdata", downloadWholeDirDir)
		require.NoError(t, err)

		cmd := exec.Command("ls -R", downloadWholeDirDir)
		lsResult, err := cmd.Output()
		require.NoError(t, err)

		assertFilesViaRemoteRun(t, sshClient, "ls -R /tmp/testdata", string(lsResult))
	})
}

func TestSSHFileDownloadBytes(t *testing.T) {
	test := sshtesting.ShouldNewTest(t, "TestSSHFileDownloadBytes")

	sshClient := startContainerAndClient(t, test)

	const expectedFileContent = "Some test data"

	// preparing file to download
	err := sshClient.Command(fmt.Sprintf(`echo -n '%s' > /tmp/testfile`, expectedFileContent)).Run(context.Background())
	require.NoError(t, err)

	t.Run("Download bytes", func(t *testing.T) {
		cases := []struct {
			title      string
			remotePath string
			tmpDirName string
			wantErr    bool
			err        string
		}{
			{
				title:      "Positive result",
				remotePath: "/tmp/testfile",
				tmpDirName: os.TempDir(),
				wantErr:    false,
			},
			{
				title:      "Unaccessible tmp",
				remotePath: "/tmp/testfile",
				tmpDirName: "/var/lib",
				wantErr:    true,
				err:        "create target tmp file",
			},
			{
				title:      "Unaccessible remote file",
				remotePath: "/etc/sudoers",
				tmpDirName: os.TempDir(),
				wantErr:    true,
				err:        "download target tmp file",
			},
		}

		for _, c := range cases {
			t.Run(c.title, func(t *testing.T) {
				f := sshClient.File()
				bytes, err := f.DownloadBytes(context.Background(), c.remotePath)
				if c.wantErr {
					require.Error(t, err)
					require.Contains(t, err.Error(), c.err)
				}

				require.NoError(t, err)
				// out contains a contant of uploaded file, should be equal to testFile contant
				require.Equal(t, expectedFileContent, string(bytes))
			})
		}
	})
}
