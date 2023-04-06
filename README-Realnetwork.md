# Extending Nyx-Net for Fuzzing Libraries that hook Socket API Using Real Network Mode

  ## Introduction

  Nyx-Net is a powerful fuzzer for fuzzing TCP servers using memory snapshots.
  However, its current implementation does not support fuzzing libraries that intercept Socket API calls.
  Applying such a library to a target application will conflict with Nyx-Net's way of delivering fuzzed input.
  In this document, an extended functionality that allows Nyx-Net to pass data to target applications
  using a real network is introduced, enabling it to fuzz such libraries.

  ## Motivation

  Many libraries intercept Socket API calls. An example is [OpenOnload](https://github.com/Xilinx-CNS/onload),
  a user-level network stack, which accelerates TCP and UDP network I/O for applications using the BSD sockets on Linux.

  The easiest way of fuzzing such libraries is to use them on some network application as usual and fuzz that application.
  This way, the data passed to the app will eventually be captured by the desired library. We can collect coverage from it too
  by compiling the library with afl-gcc/clang compiler or, even simpler, by using Intel PT.

  However, we cannot do it with native Nyx-Net since both Nyx-Net and the target library will intercept Socket API calls.
  For example, Nyx-Net hooks the `recv` function in a way that the buffer is filled with fuzzed input, but the real function never invokes.

  ## Proposed Functionality

  To address these issues, we propose a mechanism that allows Nyx-Net to send data over a real network.
  This mechanism involves implementing a TCP/UDP client directly inside the Nyx-Net agent embedded into the target application.

  It is worth noting that **it's possible to use real network mode to fuzz applications as usual, without such a library**.
  However, one should better use native Nyx-Net, since its network emulation layer results in a significantly faster speed.
  A general rule of thumb is switching to the real network **reduces speed by two orders of magnitude**.

  ## Review of Conventional Data Transferring

  Let's recall the mechanism of transferring data to an application during Nyx-Net operation using a TCP server as an example.

  By using LD_PRELOAD Nyx-Net embeds a so-called "Agent" into the application that will intercept Socket API functions.
  Its job is to detect when the target application is ready to accept input, make a snapshot, and start transferring mutated data.
  In the case of TCP, for example, the snapshot is made when sever invokes `recv` for the first time.
  Note that the TCP handshake is already done, so we won't be performing it on each iteration.

  It's important to note that the actual recv function is never called.
  The agent simply fills the appropriate buffer with data received from the fuzzer.

  ## Proposed Way of Transferring Data

  To transfer data to the target server via a real network we need some clients to do so.

  (FIXME: for now only TCP client is implemented)

  It is possible to interact with the target server via a loopback interface, however, it's better to put the client and server in different
  network namespaces. This helps isolate the client from the rest of the system, plus, libraries like OpenOnload which
  designed for real-world use simply do not support servers that run on a loopback interface, it has no real-world use cases.
  However, with network namespaces, the client and server will use a pair of virtual ethernet devices (veth).

  ```
  ┌────────────────────────────────────────────┐
  │                                            │
  │ ┌──────────────────────┐                   │
  │ │                      │                   │
  │ │                ┌─────┤             ┌─────┤
  │ │                │     │             │     │
  │ │                │veth1│◄───────────►│veth0│
  │ │                │     │             │     │
  │ │                └─────┤             └─────┤
  │ │              nspce   │                   │
  │ └──────────────────────┘                   │
  │                                            │
  │                              Host namespace│
  └────────────────────────────────────────────┘
  ```

  (FIXME: For now "nspce" name is hardcoded as a namespace name)

  The LD_PRELOAD chain embeds the underlying library `target_lib.so` that intercepts Socket API calls
  into the target application first, followed by the Agent `ld_preload_fuzz.so`.

  Note that the "underlying library" could be just a libc, i.e we can fuzz any network application as usual,
  but transfer data to it via network instead of hooks.

  ### Data transfer workflow

  1. The Nyx-Net agent replaces the listen function with the listen function from the underlying library and then creates a new thread.
  2. The thread is moved to a separate network namespace and acts as a client. Its job is to receive data from the fuzzer and transfer it.
  3. The thread connects to the server using the _real_ `connect` function and then idles, waiting for the fuzzer's notification to transfer data.
  4. Server calls _hooked_ `accept`, TCP handshake is established.
  5. Server calls _hooked_ `recv` function that does the following:
      1. Invokes memory snapshot, capturing the server and client after the TCP handshake.
      2. Gets data from the fuzzer as usual, using the `handle_next_packet()` function.
      3. Stores received data in a shared variable and notify the thread.
      3. Calls _real_ `recv`.
  6. When the thread receives a notification it sends the data stored in a shared variable using the _real_ `write` function and then terminates.
  7. Client will eventually get the data from its _hooked_ `recv` function invocation and starts processing it.
  8. After the data has been processed, the memory snapshot is restored and the process starts again.

  You can see this process clearly in the following scheme:

  - `read` --- real libc function
  - `read*` --- `target_lib.so` hooked function
  - `read**` --- Nyx-Net's Agent hooked function

  ```
  ┌──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │                                                                                                                      │
  │ ┌──────────────────────────────────────┐                                                                             │
  │ │                                      │                                                                             │
  │ │ ┌───────────────────────┐    ┌───────┤                                                            ┌───────┐        │
  │ │ │                       │    │       │                Real network connection                     │       │        │
  │ │ │        Client         │◄──►│ veth1 ◄────────────────────────────────────────────────────────────► veth0 │        │
  │ │ │                       │    │       │                                                            │       │        │
  │ │ │      ┌────────┐       │    └───────┤                                                            └───┬───┘        │
  │ │ │      │socket  │       │            │                                                                │            │
  │ │ │      └──┬─────┘       │            │                                                                │            │
  │ │ │         │             │            │                                                                │            │
  │ │ │      ┌──┴─────┐       │            │                                                                │            │
  │ │ │      │connect │       │            │    ┌─────────────────────────────────────────┐                 │            │
  │ │ │      └──┬─────┘       │            │    │ Data transfer workflow                  │                 │            │
  │ │ │         │             │            │    │                             ┌────────┐  │                 │            │
  │ │ │   ┌─────┴────────┐    │            │    │                             │socket* │  │                 │            │
  │ │ │   │ wait for the │    │            │    │                             └──┬─────┘  │                 │            │
  │ │ │ ┌─► notification │    │            │    │                                │        │                 │            │
  │ │ │ │ └─────┬────────┘    │            │    │ ┌───────────┐    hooks as   ┌──┴─────┐  │                 │            │
  │ │ │ │       │             │            │    │ │   bind*   │◄──────────────┤bind**  │  │                 │            │
  │ │ │ │ ┌─────┴───────────┐ │            │    │ └───────────┘               └──┬─────┘  │                 │            │
  │ │ │ │ │write(shared buf)│ │            │    │                                │        │                 │            │
  │ │ │ │ └─────────────────┘ │            │    │ ┌───────────────┐           ┌──┴─────┐  │                 │            │
  │ │ │ │                     │            │    │ │    listen*    │◄──────────┤listen**│  │                 │            │
  │ │ └─┼─────────────────────┘            │    │ │               │           └──┬─────┘  │    ┌────────────▼──────────┐ │
  │ │   │                                  │    │ │ Create thread │              │        │    │                       │ │
  │ │   │      Separate network namespace  │    │ └───────────────┘              │        │    │      Target Server    │ │
  │ └───┼──────────────────────────────────┘    │                                │        │    │                       │ │
  │     │                                       │ ┌──────────────┐            ┌──┴─────┐  │    │ ┌───────────────────┐ │ │
  │     │                                       │ │    accept*   │◄───────────┤accept**│  │    │ │    target_lib.so  │ │ │
  │     │                                       │ └──────────────┘            └──┬─────┘  │    │ │                   │ │ │
  │     │                                       │                                │        ├────┤ │ ┌───────────────┐ │ │ │
  │     │                                       │                                │        │    │ │ │ld_preload_fuzz│ │ │ │
  │     │                                       │                                │        │    │ │ └───────────────┘ │ │ │
  │     │                                       │                                │        │    │ │                   │ │ │
  │     │                                       │  ┌───────────────────────┐     │        │    │ └───────────────────┘ │ │
  │     │                                       │  │ Create memory snapshot│     │        │    │                       │ │
  │     │                                       │  │                       │     │        │    └───────────────────────┘ │
  │     │                                       │  │ Fill shared buf with  │     │        │                              │
  │     │                                       │  │ data from fuzzer via  │  ┌──┴─────┐  │                              │
  │     │                                       │  │ `handle_next_packet`  │◄─┤read**  │  │                              │
  │     │                                       │  │                       │  └────────┘  │                              │
  │     └───────────────────────────────────────┼──┼────Notify thread      │              │                              │
  │                                             │  │                       │              │                              │
  │                                             │  │    read*              │              │                              │
  │                                             │  │                       │              │                              │
  │                                             │  └───────────────────────┘              │                              │
  │                                             │                                         │                              │
  │                                             └─────────────────────────────────────────┘                              │
  │                                                                                                                      │
  └──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
  ```

  ## Usage

  An example of fuzzing LightFTP using a real network without any Socket-API-intercepting-library:

  This guide uses a full-blown virtual machine as a base image for fuzzing, but the Nyx-Net's simple
  rootfs implementation should also work if one adds the `net-tools` package here.

  1. Set up regular distribution as a base image for fuzzing but stop before the `sudo ./loader` step.
     Here's the guide for that: [guide](https://github.com/nyx-fuzz/Nyx/blob/main/docs/01-Nyx-VMs.md).

  2. Invoke the following commands to create a "nspce" network namespace and a pair of
     virtual ethernet devices connecting the main namespace with created one.

     ```bash
     # create a network namespace
     sudo ip netns add nspce
     # Create a veth pair
     sudo ip link add veth0 type veth peer name veth1
     # Move veth1 to the new namespace
     sudo ip link set veth1 netns nspce
     # Bring loopback interface up
     sudo ip netns exec nscpe ip link set dev lo up
     # Assign ip to interface in the new namespace
     sudo ip netns exec nscpe ip addr add 10.0.0.2/24 dev veth1
     sudo ip netns exec nscpe ip link set dev veth1 up
     # Assign ip to interface in the host namespace
     sudo ip addr add 10.0.0.1/24 dev veth0
     sudo ip link set dev veth0 up
     ```

  3. Call `sudo ./loader` and continue following the guide.

  4. Change `127.0.0.1` to `10.0.0.1` in `targets/extra_folders/lightftp_extra_folder/fftp.conf`.

  5. Pack LightFTP using conventional `targets/packer_scripts/pack_lightftp.sh` script with the following
     modifications:

   ```diff
   diff --git a/targets/packer_scripts/pack_lightftp.sh b/targets/packer_scripts/pack_lightftp.sh
   --- a/targets/packer_scripts/pack_lightftp.sh
   +++ b/targets/packer_scripts/pack_lightftp.sh
   @@ -15,9 +15,13 @@ python3 $PACKER ../setup_scripts/build/lightftp/LightFTP-gcov/Source/Release/fft
    --purge \
    --nyx_net \
    --nyx_net_port 2200 \
   +--nyx_net_ip 10.0.0.1 \
   +--nyx_net_real_network_mode \
    -spec ../specs/ftp \
    -args "fftp.conf 2200" \
    --setup_folder ../extra_folders/lightftp_extra_folder && \
   -python3 $CONFIG_GEN $SHAREDIR Kernel -s ../specs/ftp/lightftpd/ -d ../dicts/ftp.dict $DEFAULT_CONFIG
   +python3 $CONFIG_GEN $SHAREDIR Snapshot -m 2048 -s ../specs/ftp/lightftpd/ -d ../dicts/ftp.dict $DEFAULT_CONFIG
   ```

   6. Run the fuzzer as usual.

  Expect about **30-40 execs/sec** instead of **3000-4000 execs/sec**, but the fuzzer will use a real network to transfer data.
