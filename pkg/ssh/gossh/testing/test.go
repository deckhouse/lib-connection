// Copyright 2026 Flant JSC
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

package ssh_testing

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deckhouse/lib-dhctl/pkg/log"
	"github.com/name212/govalue"
	"github.com/stretchr/testify/require"
)

const (
	randomSuffixSeparator = "."
)

type Test struct {
	LocalTmpDir string
	ID          string
	Logger      *log.InMemoryLogger

	testName    string
	subTestName string
}

func ShouldNewTest(t *testing.T, testName string) *Test {
	CheckSkipSSHTest(t, testName)

	err := os.Setenv("SSH_AUTH_SOCK", "")
	require.NoError(t, err, "Cleanup SSH_AUTH_SOCK")

	tst, err := NewTest(testName)
	require.NoError(t, err, "failed to create Test '%s'", testName)
	tst.RegisterCleanup(t)
	return tst
}

func NewTest(testName string) (*Test, error) {
	if testName == "" {
		return nil, fmt.Errorf("testName is empty")
	}

	id := GenerateID(testName)

	resTest := &Test{
		testName: testName,
		ID:       id,
	}

	if govalue.Nil(resTest.Logger) {
		resTest.Logger = TestLogger()
	}

	localTmpDirStr := filepath.Join(os.TempDir(), tmpGlobalDirName, id)

	err := os.MkdirAll(localTmpDirStr, 0777)
	if err != nil {
		return nil, resTest.WrapError("failed to create local tmp dir %s: %v", localTmpDirStr, err)
	}

	resTest.LocalTmpDir = localTmpDirStr

	return resTest, nil
}

func (s *Test) IsZero() bool {
	return s.LocalTmpDir == "" || s.ID == "" || s.testName == ""
}

var forReplace = []string{" ", ",", ".", "-"}

func (s *Test) SetSubTest(names ...string) *Test {
	resName := ""

	l := len(names)
	if l > 0 {
		tests := make([]string, 0, l)
		for _, name := range names {
			for _, old := range forReplace {
				name = strings.ReplaceAll(name, old, "_")
			}
			tests = append(tests, name)
		}
		resName = strings.Join(tests, "/")
	}

	s.subTestName = resName
	return s
}

func (s *Test) WrapError(format string, args ...any) error {
	f := s.Name() + ": " + format
	return fmt.Errorf(f, args...)
}

func (s *Test) WrapErrorWithAfterName(aftername, format string, args ...any) error {
	f := fmt.Sprintf("%s (%s): ", s.Name(), aftername) + format
	return fmt.Errorf(f, args...)
}

func (s *Test) Name() string {
	res := s.testName
	if s.subTestName != "" {
		res = fmt.Sprintf("%s/%s", res, s.subTestName)
	}

	return res
}

func (s *Test) MustMkSubDirs(t *testing.T, dirs ...string) string {
	testDir, err := s.MkSubDirs(dirs...)
	require.NoError(t, err, "MustMkSubDirs should create sub dirs")

	return testDir
}

func (s *Test) MustCreateTmpFile(t *testing.T, content string, executable bool, pathInTestDir ...string) string {
	result, err := s.CreateTmpFile(content, executable, pathInTestDir...)
	require.NoError(t, err, "MustCreateTmpFile should create tmp file")
	return result
}

func (s *Test) MustCreateFile(t *testing.T, content string, executable bool, pathInTestDir ...string) string {
	result, err := s.CreateFile(content, executable, pathInTestDir...)
	require.NoError(t, err, "MustCreateFile should create file")

	return result
}

func (s *Test) CreateTmpFile(content string, executable bool, pathInTestDir ...string) (string, error) {
	if err := s.validateCreateDirsFilesArgs(pathInTestDir...); err != nil {
		return "", err
	}

	filePrefix, subDirs := s.fileNameAndSubDirs(pathInTestDir...)

	suffix := GenerateID(fmt.Sprintf("%s/%s", s.testName, filePrefix))

	fileName := addRandomSuffix(filePrefix, suffix)

	return s.CreateFile(content, executable, append(subDirs, fileName)...)
}

func (s *Test) CreateFileWithSameSuffix(sourceFile string, content string, executable bool, pathInTestDir ...string) (string, error) {
	if err := s.validateCreateDirsFilesArgs(pathInTestDir...); err != nil {
		return "", err
	}

	if sourceFile == "" {
		return "", fmt.Errorf("source file is empty for file")
	}

	sourceFileBase := filepath.Base(sourceFile)

	fileNameSeparated := strings.Split(sourceFileBase, randomSuffixSeparator)
	if len(fileNameSeparated) < 2 {
		return "", fmt.Errorf("suffix is empty for file %s", sourceFile)
	}

	l := len(fileNameSeparated)

	sourceName := fileNameSeparated[l-2]

	fileName, subDirs := s.fileNameAndSubDirs(pathInTestDir...)

	if sourceName == fileName {
		return "", fmt.Errorf("source file name %s is same as destination for file %s", fileName, sourceFile)
	}

	resFileName := addRandomSuffix(fileName, fileNameSeparated[l-1])

	return s.CreateFile(content, executable, append(subDirs, resFileName)...)
}

func (s *Test) CreateFile(content string, executable bool, pathInTestDir ...string) (string, error) {
	if err := s.validateCreateDirsFilesArgs(pathInTestDir...); err != nil {
		return "", err
	}

	fileName, subDirs := s.fileNameAndSubDirs(pathInTestDir...)

	fullPathSlice := []string{s.LocalTmpDir}
	if len(subDirs) > 0 {
		if _, err := s.MkSubDirs(subDirs...); err != nil {
			return "", fmt.Errorf("failed to create sub dirs: %v", err)
		}

		fullPathSlice = append(fullPathSlice, subDirs...)
	}

	fullPathSlice = append(fullPathSlice, fileName)

	fullPath := filepath.Join(fullPathSlice...)

	mode := os.FileMode(0666)
	if executable {
		mode = os.FileMode(0755)
	}

	err := os.WriteFile(fullPath, []byte(content), mode)
	if err != nil {
		return "", s.WrapError("failed to create file %s: %v", fullPath, err)
	}

	return fullPath, nil
}

func (s *Test) MkSubDirs(dirs ...string) (string, error) {
	if err := s.validateCreateDirsFilesArgs(dirs...); err != nil {
		return "", err
	}

	fullPathSlice := append([]string{s.LocalTmpDir}, dirs...)
	testDir := filepath.Join(fullPathSlice...)

	if err := os.MkdirAll(testDir, 0755); err != nil {
		return "", s.WrapError("failed to create test dir %s: %v", testDir, err)
	}

	return testDir, nil
}

func (s *Test) validateCreateDirsFilesArgs(paths ...string) error {
	if len(paths) == 0 {
		return s.WrapError("paths parts is empty")
	}

	if s.LocalTmpDir == "" {
		return s.WrapError("LocalTmpDir is empty")
	}

	return nil
}

func (s *Test) RegisterCleanup(t *testing.T) {
	t.Cleanup(func() {
		s.Cleanup(t)
	})
}

func (s *Test) Cleanup(t *testing.T) {
	if s.LocalTmpDir == "" || s.LocalTmpDir == "/" {
		return
	}

	err := os.RemoveAll(s.LocalTmpDir)
	if err != nil && !os.IsNotExist(err) {
		LogErrorOrAssert(t, fmt.Sprintf("Remove local tmp dir: %s", s.LocalTmpDir), err, s.Logger)
		return
	}

	if !govalue.Nil(s.Logger) {
		s.Logger.InfoF("Temp dir removed for test %s: %s", s.Name(), s.LocalTmpDir)
	}
}

func (s *Test) fileNameAndSubDirs(pathInTestDir ...string) (string, []string) {
	l := len(pathInTestDir)

	if l == 1 {
		return pathInTestDir[0], nil
	}

	return pathInTestDir[l-1], pathInTestDir[:l-1]
}

func addRandomSuffix(name string, suffix string) string {
	return fmt.Sprintf("%s%s%s", name, randomSuffixSeparator, suffix)
}
