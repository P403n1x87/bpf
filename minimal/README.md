Checkout the libbpf source and compile it with

~~~
cd src
make
~~~

Create a symbolic link to the `src` folder to a local `bpf` folder along with
your sources.

Get the `bpftool` binary from
https://github.com/libbpf/libbpf-bootstrap/tree/master/tools and put it in the
parent folder.

Compile the project and run as super-user and setting `LD_LIBRARY_PATH=bpf`,
e.g.

~~~
sudo LD_LIBRARY_PATH=bpf ./minimal
~~~