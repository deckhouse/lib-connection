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

package ssh_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	connection "github.com/deckhouse/lib-connection/pkg"
	sshconfig "github.com/deckhouse/lib-connection/pkg/ssh/config"
	"github.com/deckhouse/lib-connection/pkg/ssh/gossh"
	"github.com/deckhouse/lib-connection/pkg/tests"
)

func TestFileUpload(t *testing.T) {
	type uploadTest struct {
		unaccessibleDir string
		dir             string
		file            string
		symlink         string
		fileContent     string
	}

	createTest := func(t *testing.T) (*tests.Test, uploadTest) {
		test := tests.ShouldNewIntegrationTest(t, "TestFileUpload")

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

		return test, uploadTest{
			unaccessibleDir: unaccessibleDirectoryPath,
			dir:             testDir,
			file:            testFile,
			symlink:         symlink,
			fileContent:     testFileContent,
		}
	}

	providers := []sshTestClientProvider{
		onlyTargetSSHClientProvider,
		viaBastionSSHClientProvider,
	}

	runTests := []runTest{
		{
			name: "Go",
			mode: sshconfig.Mode{
				ForceModern: true,
			},
		},

		{
			name: "Cli",
			mode: sshconfig.Mode{
				ForceLegacy: true,
			},
		},
	}

	runUpload := func(t *testing.T, sshClient connection.SSHClient, ut uploadTest) {
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
					srcPath: ut.file,
					dstPath: ".",
					wantErr: false,
				},
				{
					title:   "Directory",
					srcPath: ut.dir,
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
					srcPath: ut.file,
					dstPath: "/any",
					wantErr: true,
				},
				{
					title:   "File to /var/lib",
					srcPath: ut.file,
					dstPath: "/var/lib",
					wantErr: true,
				},
				{
					title:   "File to unaccessible file",
					srcPath: ut.file,
					dstPath: "/path/what/not/exists.txt",
					wantErr: true,
				},
				{
					title:   "Directory to root",
					srcPath: ut.dir,
					dstPath: "/",
					wantErr: true,
				},
				{
					title:   "Symlink",
					srcPath: ut.symlink,
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
					srcPath: ut.unaccessibleDir,
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
					f := sshClient.File()
					err := f.Upload(context.Background(), c.srcPath, c.dstPath)
					if c.wantErr {
						require.Error(t, err)
						require.Contains(t, err.Error(), c.err)
						return
					}

					require.NoError(t, err)
				})
			}
		})
	}

	runContentEquality := func(t *testing.T, sshClient connection.SSHClient, container *tests.TestContainerWrapper, ut uploadTest) {
		t.Run("Equality of uploaded and local file content", func(t *testing.T) {
			f := sshClient.File()
			err := f.Upload(context.Background(), ut.file, "/tmp/testfile.txt")
			require.NoError(t, err, "should upload file")

			assertFilesOut(t, sshClient, container, ut.fileContent, "cat", "/tmp/testfile.txt")
		})
	}

	runDirEquality := func(t *testing.T, sshClient connection.SSHClient, container *tests.TestContainerWrapper, ut uploadTest) {
		t.Run("Equality of uploaded and local directory", func(t *testing.T) {
			f := sshClient.File()
			err := f.Upload(context.Background(), ut.dir, "/tmp/upload")
			require.NoError(t, err, "should upload dir")

			cmd := exec.Command("ls", ut.dir)
			lsResult, err := cmd.Output()
			require.NoError(t, err, "should exec local ls")

			assertFilesOut(t, sshClient, container, string(lsResult), "ls", "/tmp/upload")
		})
	}

	for _, rt := range runTests {
		t.Run(rt.name, func(t *testing.T) {
			for _, p := range providers {
				t.Run(p.name, func(t *testing.T) {
					test, ut := createTest(t)
					client, container := p.provider(t, test, rt)
					runUpload(t, client, ut)
					runContentEquality(t, client, container, ut)
					runDirEquality(t, client, container, ut)
				})
			}
		})
	}
}

func TestFileUploadBytes(t *testing.T) {
	test := tests.ShouldNewIntegrationTest(t, "TestSSHFileUploadBytes")

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
	test := tests.ShouldNewIntegrationTest(t, "TestSSHFileDownload")

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
	test := tests.ShouldNewIntegrationTest(t, "TestSSHFileDownloadBytes")

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
