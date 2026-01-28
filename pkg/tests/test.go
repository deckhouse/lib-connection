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

package tests

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deckhouse/lib-dhctl/pkg/log"
	"github.com/name212/govalue"
	"github.com/stretchr/testify/require"

	"github.com/deckhouse/lib-connection/pkg/settings"
)

const (
	tmpGlobalDirName      = "test-lib-connection"
	randomSuffixSeparator = "."
)

type testOpts struct {
	isDebug     bool
	parallelRun bool
}
type TestOpt func(opts *testOpts)

func TestWithDebug(isDebug bool) TestOpt {
	return func(opts *testOpts) {
		opts.isDebug = isDebug
	}
}

func TestWithParallelRun(p bool) TestOpt {
	return func(opts *testOpts) {
		opts.parallelRun = p
	}
}

func applyTestOpts(opts ...TestOpt) testOpts {
	options := testOpts{}
	for _, opt := range opts {
		opt(&options)
	}

	return options
}

type Test struct {
	tmpDir string
	id     string
	Logger *log.InMemoryLogger

	testName    string
	subTestName string

	options testOpts

	settings *settings.BaseProviders
}

func ShouldNewTest(t *testing.T, testName string, opts ...TestOpt) *Test {
	CheckSkipSSHTest(t, testName)

	if applyTestOpts(opts...).parallelRun && runParallelFromEnv() {
		t.Parallel()
	}

	err := os.Setenv("SSH_AUTH_SOCK", "")
	require.NoError(t, err, "cleanup SSH_AUTH_SOCK env")

	tst, err := NewTest(testName, opts...)
	require.NoError(t, err, "failed to create Test '%s'", testName)

	tst.RegisterCleanup(t)
	return tst
}

func NewTest(testName string, opts ...TestOpt) (*Test, error) {
	if testName == "" {
		return nil, fmt.Errorf("testName is empty")
	}

	options := applyTestOpts(opts...)

	id := GenerateID(testName)

	resTest := &Test{
		testName: testName,
		id:       id,
		options:  options,
	}

	if govalue.Nil(resTest.Logger) {
		resTest.Logger = TestLogger(options.isDebug)
	}

	localTmpDirStr := filepath.Join(os.TempDir(), tmpGlobalDirName, id)

	err := os.MkdirAll(localTmpDirStr, 0777)
	if err != nil {
		return nil, resTest.WrapError("failed to create local tmp dir %s: %v", localTmpDirStr, err)
	}

	resTest.tmpDir = localTmpDirStr

	resTest.Logger.InfoF("Created tmp dir '%s' for test '%s'", resTest.tmpDir, resTest.testName)

	resTest.settings = settings.NewBaseProviders(settings.ProviderParams{
		LoggerProvider: log.SimpleLoggerProvider(resTest.Logger),
		IsDebug:        options.isDebug,
		TmpDir:         resTest.tmpDir,
	})

	return resTest, nil
}

func (s *Test) IsZero() bool {
	return s.TmpDir() == "" || s.GetID() == "" || s.Name() == ""
}

func (s *Test) Settings() settings.Settings {
	return s.settings
}

func (s *Test) WithEnvsPrefix(p string) *Test {
	s.settings = s.settings.Clone(settings.CloneWithEnvsPrefix(p))
	return s
}

func (s *Test) GetLogger() *log.InMemoryLogger {
	return s.Logger
}

func runParallelFromEnv() bool {
	if v, ok := os.LookupEnv("RUN_TESTS_SEQUENTIALLY"); ok && v == "true" {
		return false
	}

	return true
}

func (s *Test) RunSubTestParallel(t *testing.T) {
	if runParallelFromEnv() {
		t.Parallel()
	}
}

func (s *Test) SetSubTest(names ...string) *Test {
	resName := prepareTestNames(names...)
	if resName == "" {
		return s
	}

	s.subTestName = strings.TrimPrefix(resName, s.Name()+"/")

	return s
}

func (s *Test) WrapError(format string, args ...any) error {
	f := s.FullName() + ": " + format
	return fmt.Errorf(f, args...)
}

func (s *Test) WrapErrorWithAfterName(aftername, format string, args ...any) error {
	f := fmt.Sprintf("%s (%s): ", s.FullName(), aftername) + format
	return fmt.Errorf(f, args...)
}

func (s *Test) FullName() string {
	res := s.Name()
	if s.subTestName != "" {
		res = fmt.Sprintf("%s/%s", res, s.subTestName)
	}

	return res
}

func (s *Test) Name() string {
	return s.testName
}

func (s *Test) GetID() string {
	return s.id
}

func (s *Test) GenerateID(names ...string) string {
	fullNames := []string{
		s.Name(),
	}
	fullNames = append(fullNames, names...)
	return GenerateID(fullNames...)
}

func (s *Test) TmpDir() string {
	return s.tmpDir
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

	suffix := GenerateID(s.FullName(), filePrefix)

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
	suffix := fileNameSeparated[l-1]

	fileName, subDirs := s.fileNameAndSubDirs(pathInTestDir...)

	if sourceName == fileName {
		return "", fmt.Errorf("source file name %s is same as destination for file %s", fileName, sourceFile)
	}

	resFileName := addRandomSuffix(fileName, suffix)

	return s.CreateFile(content, executable, append(subDirs, resFileName)...)
}

func (s *Test) CreateFile(content string, executable bool, pathInTestDir ...string) (string, error) {
	if err := s.validateCreateDirsFilesArgs(pathInTestDir...); err != nil {
		return "", err
	}

	fileName, subDirs := s.fileNameAndSubDirs(pathInTestDir...)

	fullPathSlice := []string{s.TmpDir()}
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

	fullPathSlice := append([]string{s.TmpDir()}, dirs...)
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

	if s.TmpDir() == "" {
		return s.WrapError("tmpDir is empty")
	}

	return nil
}

func (s *Test) RegisterCleanup(t *testing.T) {
	t.Cleanup(func() {
		s.Cleanup(t)
	})
}

func (s *Test) Cleanup(t *testing.T) {
	tmpDir := s.TmpDir()
	if tmpDir == "" || tmpDir == "/" {
		return
	}

	err := os.RemoveAll(tmpDir)
	if err != nil && !os.IsNotExist(err) {
		LogErrorOrAssert(t, fmt.Sprintf("Remove local tmp dir: %s", tmpDir), err, s.Logger)
		return
	}

	logger := s.GetLogger()
	if !govalue.Nil(logger) {
		logger.InfoF("Temp dir '%s' removed for test '%s'", tmpDir, s.FullName())
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

func (s *Test) SetTmpDir(dir string) error {
	stats, err := os.Stat(dir)
	if err != nil {
		return err
	}

	if !stats.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	localTmpDirStr := filepath.Join(dir, tmpGlobalDirName, s.id)

	err = os.MkdirAll(localTmpDirStr, 0777)
	if err != nil {
		return fmt.Errorf("failed to create local tmp dir %s: %v", localTmpDirStr, err)
	}

	s.tmpDir = localTmpDirStr
	return nil
}

func (s *Test) MustCreateUnaccessibleDir(t *testing.T, name string) {
	fullName := filepath.Join(s.tmpDir, name)
	require.NoDirExists(t, fullName)

	err := os.MkdirAll(fullName, 0o100)
	require.NoError(t, err)
}
