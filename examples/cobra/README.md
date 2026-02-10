# examples/cobra

This example shows that you can use library with cobra package.

## Build

```bash
go build -o cobra main.go
```

## Example commands
```bash
./cobra kube-only --tmp-dir=/tmp/my-cobra --kubeconfig=~/my.kind.kubeconfig --kubeconfig-context=kind-my --print-warnin

./cobra ssh --ssh-user=ubuntu --ssh-host=0.0.0.0
./cobra ssh --ssh-user=ubuntu --ssh-host=0.0.0.0 --use-standalone-kube --kubeconfig=~/my.kind.kubeconfig
./cobra ssh --ssh-user=ubuntu --ssh-host=0.0.0.0 --ssh-agent-private-keys=~/.ssh/id_rsa --ssh-agent-private-keys=~/.ssh/another
```