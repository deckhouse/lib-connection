# examples/cobra

This example shows that you can use library with cobra package.

## Build

```bash
mkdir -p bin
go build -o bin/cobra main.go
```

## Example commands
```bash
bin/cobra kube-only --tmp-dir=/tmp/my-cobra --kubeconfig=~/my.kind.kubeconfig --kubeconfig-context=kind-my --print-warning

bin/cobra ssh --ssh-user=ubuntu --ssh-host=0.0.0.0

bin/cobra ssh --ssh-user=ubuntu --ssh-host=0.0.0.0 --use-standalone-kube --kubeconfig=~/my.kind.kubeconfig

bin/cobra ssh --ssh-user=ubuntu --ssh-host=0.0.0.0 --ssh-agent-private-keys=~/.ssh/id_rsa --ssh-agent-private-keys=~/.ssh/another

bin/cobra ssh-additional --ssh-user=ubuntu --kubeconfig=~/my.kind.kubeconfig

SSH_HOST_CONNECT=0.0.0.0 bin/cobra ssh-additional --ssh-user=ubuntu

SSH_HOST_CONNECT=0.0.0.0 bin/cobra ssh-additional --ssh-user=ubuntu --kubeconfig=~/kind.kubeconfig
```