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

package testssh

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/deckhouse/lib-connection/pkg/ssh/gossh"
	sshtesting "github.com/deckhouse/lib-connection/pkg/tests"
)

func TestFileUpload(t *testing.T) {
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

	symlink := filepath.Join(test.TmpDir(), "symlink")
	err := os.Symlink(testFile, symlink)
	require.NoError(t, err)

	const unaccessibleDirectoryName = "unaccessible"
	test.MustCreateUnaccessibleDir(t, unaccessibleDirectoryName)
	unaccessibleDirectoryPath := filepath.Join(test.TmpDir(), unaccessibleDirectoryName)

	goSSHClient, cliSSHClient, goSSHClient2, err := startTwoContainersWithClients(t, test, false)
	require.NoError(t, err)

	prepareScp(t)

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
				srcPath: unaccessibleDirectoryPath,
				dstPath: ".",
				wantErr: true,
			},
			{
				title:   "Unaccessible file",
				srcPath: "/etc/sudoers",
				dstPath: ".",
				wantErr: true,
			},
		}

		for _, c := range cases {
			t.Run(c.title, func(t *testing.T) {
				f := goSSHClient.File()
				f2 := cliSSHClient.File()
				err = f.Upload(context.Background(), c.srcPath, c.dstPath)
				err2 := f2.Upload(context.Background(), c.srcPath, c.dstPath)
				if !c.wantErr {
					require.NoError(t, err)
					require.NoError(t, err2)
				} else {
					require.Error(t, err)
					require.Contains(t, err.Error(), c.err)
					require.Error(t, err2)
					require.Contains(t, err2.Error(), c.err)
				}
			})
		}
	})

	t.Run("Equality of uploaded and local file content", func(t *testing.T) {
		f := goSSHClient.File()
		err := f.Upload(context.Background(), testFile, "/tmp/testfile.txt")
		// testFile contains "Hello world" string
		require.NoError(t, err)

		assertFilesViaRemoteRun(t, goSSHClient.(*gossh.Client), "cat /tmp/testfile.txt", testFileContent)

		// clissh check
		f = cliSSHClient.File()
		err = f.Upload(context.Background(), testFile, "/tmp/testfile.txt")
		require.NoError(t, err)

		err = goSSHClient2.Start()
		require.NoError(t, err)
		registerStopClient(t, goSSHClient2)

		assertFilesViaRemoteRun(t, goSSHClient2.(*gossh.Client), "cat /tmp/testfile.txt", testFileContent)
	})

	t.Run("Equality of uploaded and local directory", func(t *testing.T) {
		f := goSSHClient.File()
		err := f.Upload(context.Background(), testDir, "/tmp/upload")
		require.NoError(t, err)

		cmd := exec.Command("ls", testDir)
		lsResult, err := cmd.Output()
		require.NoError(t, err)

		assertFilesViaRemoteRun(t, goSSHClient.(*gossh.Client), "ls /tmp/upload", string(lsResult))

		// clissh
		f = cliSSHClient.File()
		err = f.Upload(context.Background(), testDir, "/tmp/upload")
		require.NoError(t, err)

		err = goSSHClient2.Start()
		require.NoError(t, err)
		registerStopClient(t, goSSHClient2)

		assertFilesViaRemoteRun(t, goSSHClient2.(*gossh.Client), "ls /tmp/upload", string(lsResult))
	})
}

func TestFileUploadBytes(t *testing.T) {
	test := sshtesting.ShouldNewTest(t, "TestSSHFileUploadBytes")

	goSSHClient, cliSSHClient, goSSHClient2, err := startTwoContainersWithClients(t, test, false)
	require.NoError(t, err)

	prepareScp(t)
	err = os.MkdirAll(goSSHClient.(*gossh.Client).Settings().TmpDir(), 0o777)
	require.NoError(t, err)

	t.Run("Upload bytes", func(t *testing.T) {
		const content = "Hello world"
		f := goSSHClient.File()
		err := f.UploadBytes(context.Background(), []byte(content), "/tmp/testfile.txt")
		require.NoError(t, err)

		assertFilesViaRemoteRun(t, goSSHClient.(*gossh.Client), "cat /tmp/testfile.txt", content)

		// clissh
		f = cliSSHClient.File()
		err = f.UploadBytes(context.Background(), []byte(content), "/tmp/testfile.txt")
		require.NoError(t, err)

		err = goSSHClient2.Start()
		require.NoError(t, err)
		registerStopClient(t, goSSHClient2)

		assertFilesViaRemoteRun(t, goSSHClient2.(*gossh.Client), "cat /tmp/testfile.txt", content)
	})
}

func TestFileDownload(t *testing.T) {
	test := sshtesting.ShouldNewTest(t, "TestSSHFileDownload")

	goSSHClient, cliSSHClient, goSSHClient2, err := startTwoContainersWithClients(t, test, false)
	require.NoError(t, err)

	prepareScp(t)

	// preparing some test related data
	mustPrepareData(t, goSSHClient)
	mustPrepareData(t, cliSSHClient)

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
				dstPath: filepath.Join(testDir, "downloaded"),
				wantErr: false,
			},
			{
				title:   "Nonexistent",
				srcPath: "/path/to/nonexistent/file",
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
				// cleanup test directory to make sure previous run cannot affect current run
				os.RemoveAll(testDir)
				testDir = test.MustMkSubDirs(t, "download")
				// do test
				f := goSSHClient.File()
				err = f.Download(context.Background(), c.srcPath, c.dstPath)
				if c.wantErr {
					require.Error(t, err)
					require.Contains(t, err.Error(), c.err)
					return
				}

				require.NoError(t, err)

				_, err = os.Stat(c.dstPath)
				require.NoError(t, err, "%s path should exist after download", c.dstPath)

				// cleanup and download via clissh, then do the check again
				err = os.RemoveAll(c.dstPath)
				require.NoError(t, err)
				f = cliSSHClient.File()
				err = f.Download(context.Background(), c.srcPath, c.dstPath)
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

		f := goSSHClient.File()

		dstPath := path.Join(downloadContentDir, "testfile.txt")

		err := f.Download(context.Background(), "/tmp/testdata/first", dstPath)
		// /tmp/testdata/first contains "Some test data" string
		require.NoError(t, err)
		downloadedContent, err := os.ReadFile(dstPath)
		require.NoError(t, err)

		assertFilesViaRemoteRun(t, goSSHClient.(*gossh.Client), "cat /tmp/testdata/first", string(downloadedContent))

		// out contains a contant of uploaded file, should be equal to testFile contant
		require.Equal(t, expectedFileContent, string(downloadedContent))

		// cleanup and download via clissh, then do the check again
		err = os.Remove(dstPath)
		require.NoError(t, err)

		f = cliSSHClient.File()
		err = f.Download(context.Background(), "/tmp/testdata/first", dstPath)
		// /tmp/testdata/first contains "Some test data" string
		require.NoError(t, err)
		downloadedContent, err = os.ReadFile(dstPath)
		require.NoError(t, err)

		err = goSSHClient2.Start()
		require.NoError(t, err)
		registerStopClient(t, goSSHClient2)

		assertFilesViaRemoteRun(t, goSSHClient2.(*gossh.Client), "cat /tmp/testdata/first", string(downloadedContent))
		require.Equal(t, expectedFileContent, string(downloadedContent))
	})

	t.Run("Equality of downloaded and remote directory", func(t *testing.T) {
		downloadWholeDirDir := test.MustMkSubDirs(t, "download_dir")

		f := goSSHClient.File()
		err = f.Download(context.Background(), "/tmp/testdata", downloadWholeDirDir)
		require.NoError(t, err)

		cmd := exec.Command("ls", filepath.Join(downloadWholeDirDir, "testdata"))
		lsResult, err := cmd.Output()
		require.NoError(t, err)

		assertFilesViaRemoteRun(t, goSSHClient.(*gossh.Client), "ls /tmp/testdata/", string(lsResult))

		// cleanup and download via clissh, then do the check again
		err = os.RemoveAll(downloadWholeDirDir)
		require.NoError(t, err)

		f = cliSSHClient.File()
		err = f.Download(context.Background(), "/tmp/testdata", downloadWholeDirDir)
		require.NoError(t, err)

		cmd = exec.Command("ls", downloadWholeDirDir)
		lsResult, err = cmd.CombinedOutput()
		test.Logger.InfoF(string(lsResult))
		require.NoError(t, err)

		err = goSSHClient2.Start()
		require.NoError(t, err)
		registerStopClient(t, goSSHClient2)

		assertFilesViaRemoteRun(t, goSSHClient2.(*gossh.Client), "ls /tmp/testdata/", string(lsResult))
	})
}

func TestFileDownloadBytes(t *testing.T) {
	test := sshtesting.ShouldNewTest(t, "TestSSHFileDownloadBytes")

	goSSHClient, cliSSHClient, _, err := startTwoContainersWithClients(t, test, false)
	require.NoError(t, err)

	prepareScp(t)

	const expectedFileContent = "Some test data"

	// preparing file to download
	err = goSSHClient.Command(fmt.Sprintf(`echo -n '%s' > /tmp/testfile`, expectedFileContent)).Run(context.Background())
	require.NoError(t, err)
	err = cliSSHClient.Command(fmt.Sprintf(`echo -n '%s' > /tmp/testfile`, expectedFileContent)).Run(context.Background())
	require.NoError(t, err)

	t.Run("Download bytes", func(t *testing.T) {
		cases := []struct {
			title      string
			remotePath string
			wantErr    bool
		}{
			{
				title:      "Positive result",
				remotePath: "/tmp/testfile",
				wantErr:    false,
			},
			{
				title:      "Unaccessible remote file",
				remotePath: "/etc/sudoers",
				wantErr:    true,
			},
		}

		for _, c := range cases {
			t.Run(c.title, func(t *testing.T) {
				f := goSSHClient.File()
				bytes, err := f.DownloadBytes(context.Background(), c.remotePath)
				f2 := cliSSHClient.File()
				bytes2, err2 := f2.DownloadBytes(context.Background(), c.remotePath)
				if c.wantErr {
					require.Error(t, err)
					require.Error(t, err2)
				} else {
					require.NoError(t, err)
					require.NoError(t, err2)
					// out contains a contant of uploaded file, should be equal to testFile contant
					require.Equal(t, expectedFileContent, string(bytes))
					require.Equal(t, expectedFileContent, string(bytes2))
				}
			})
		}
	})
}
