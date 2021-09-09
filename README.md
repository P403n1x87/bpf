# BPF CO-RE tools

This is a collection of BPF CO-RE tools. They are not necessarily useful as the
main goal was to learn and experiment with eBPF.

## How to compile

These tools have been tested on Ubuntu 21.04 as the Linux kernel it ships with
comes with BTF enabled by default.

Compilation requires the following packages to be installed

~~~
sudo apt install -y libbpf-dev linux-tools-{common,generic}
~~~

This installs the headers for the [`libbpf`](https://github.com/libbpf/libbpf)
library and the `bpftool` utility for generating skeleton C headers, as required
by the `libbpf` API.

Once all the dependencies are in place, you can compile a tool with

~~~
make <tool-name>
~~~

e.g.

~~~
make profile
~~~

To compile all tools, do

~~~
make all
~~~


## Resources

These are some of the resources that I have found useful in order to get started
with eBPF.

- https://nakryiko.com/posts/libbpf-bootstrap/ - Good intro to `libbpf`
- https://qmonnet.github.io/whirl-offload/2016/09/01/dive-into-bpf/ - More useful details
- https://pingcap.com/blog/tips-and-tricks-for-writing-linux-bpf-applications-with-libbpf - The `perf_event` "catch".
- https://facebookmicrosites.github.io/bpf/blog/2020/02/20/bcc-to-libbpf-howto-guide.html - Gives you pointers to get BCC programs ported to BPF CO-RE.