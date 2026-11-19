# KernelGuard Core — Safe Demo Guide

Run this demonstration only inside a disposable Ubuntu VM. Do not test on a production or shared host. Use synthetic data only.

## 1. Enter the Core directory

```bash
git clone https://github.com/deepakvijay2420/KernelGuard.git
cd KernelGuard/kernelguard
```

## 2. Check prerequisites and build

```bash
uname -r
sudo python3 kgctl.py doctor
make clean
make
```

The target kernel must support BPF-LSM and BTF. The host also needs cgroup v2, bpffs, bpftool and the required BPF compiler/development packages. Stop if the prerequisite check reports a failure.

## 3. Run safe controller tests

```bash
python3 -m unittest discover -s tests -v
python3 kgctl.py plan -p policy/policy.hardened.yaml
```

A policy plan and passing unit tests validate controller-side logic. They do not prove that the BPF verifier accepts the object or that kernel enforcement is active.

## 4. Review the policy before live use

The example hardened policy is configured for audit mode. Review its agent names, executable allow-list, sensitive filename rules, network rules, run-as account and resource limits before applying it.

For a live test, use only a disposable VM and a reviewed test copy of the policy. Switch to enforce mode only after confirming that legitimate operations work in audit mode.

## 5. Demonstrate selected controls

The supplied Ubuntu reports in `../evidence/stage-validation/` record these specific outcomes:

- An allowed `/usr/bin/whoami` command succeeds.
- An unapproved `/usr/bin/id` execution is denied in enforce mode with `EPERM`.
- Reading a synthetic `.env` file generates a taint event.
- Reading a synthetic file named `shadow` is denied.
- A selected IPv4 connection after taint is denied in the supplied Stage 5 test.

These results describe the supplied test environment only. Do not claim that every attack, syscall, file access or network path is covered.

## 6. Observe events and clean up

Use the controller's event and status commands as documented by:

```bash
python3 kgctl.py --help
```

Only unload KernelGuard programs from the disposable VM where they were loaded, after confirming that the pinned objects belong to this test instance and managed workloads have stopped.

## What this demo does not prove

KernelGuard does not inspect prompt text or model reasoning. It demonstrates selected kernel-level OS policy enforcement. Behavioural analysis and ML detection are future scope and are not implemented.
