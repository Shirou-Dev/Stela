//! The shared native Linux environment: target and tool selection, Stela's
//! Linux environment for unchanged Linux sources, and the hosted C test
//! programs that `cargo test` runs when Cargo builds for this machine.
use std::{
    env, fs,
    path::{Path, PathBuf},
};

use stela_c_build::linux_build::{
    Tests, archive, linux_archive, out_dir, sources, upstream_build, upstream_warnings,
};
use stela_c_build::linux_capture::{self, COMMON, Captured, Projection, Unit};
use stela_c_build::native::configure;
use stela_c_build::native::hosted;

#[path = "linux_crc.rs"]
mod linux_crc;

/// The upstream sources: submodules that `cargo xtask gpu fetch` checks out.
pub const LINUX: &str = "../../third_party/linux";
pub fn require_sources() {
    require_source(LINUX);
}

fn require_source(source: &str) {
    let path = Path::new(source);
    assert!(
        path.join(".git").exists() || !path.join("Makefile").exists(),
        "{source} is not a Git checkout: a release's source archive holds the pinned sources \
         without Stela's patches applied (they are in third_party/patches); build from a clone \
         of the repository, where `cargo xtask gpu fetch` applies them"
    );
    assert!(
        path.join(".git").exists(),
        "{source} is missing; run `cargo xtask gpu fetch`"
    );
}

/// Stela's Linux environment for unchanged Linux sources, and the kernel-API
/// in `compat/linux/kernel` that they call, built once for every port.
pub struct Linux {
    /// Shared Kbuild flags and generated architecture header layout.
    pub environment: stela_c_build::linux::Environment,
    /// Generic registration units composed into the final canonical image.
    pub captured: Vec<Captured>,
    /// What hosted programs running Linux code link: the kernel-API and the
    /// host's platform services.
    pub hosted: Vec<PathBuf>,
}

/// Linux's fences, reservation objects and shared buffers.
const DMA_BUF_SOURCES: &[&str] = &[
    "dma-buf",
    "dma-buf-mapping",
    "dma-fence",
    "dma-fence-array",
    "dma-fence-chain",
    "dma-fence-unwrap",
    "dma-resv",
    "sync_file",
];
const COMPAT: &str = "src/compat";

/// Kbuild normally emits these headers before compiling the original UTS unit.
fn initial_uts_headers() -> PathBuf {
    let makefile = Path::new(LINUX).join("Makefile");
    println!("cargo:rerun-if-changed={}", makefile.display());
    let source = fs::read_to_string(makefile).expect("read pinned Linux version");
    let field = |key| {
        source
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once('=')?;
                (name.trim() == key).then_some(value.trim())
            })
            .expect("Linux version field")
    };
    let release = format!(
        "{}.{}.{}{}",
        field("VERSION"),
        field("PATCHLEVEL"),
        field("SUBLEVEL"),
        field("EXTRAVERSION")
    );
    assert!(
        release
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
    );
    let root = out_dir().join("initial-uts");
    let generated = root.join("generated");
    fs::create_dir_all(&generated).expect("create generated UTS headers");
    fs::write(
        generated.join("utsrelease.h"),
        format!("#define UTS_RELEASE {release:?}\n"),
    )
    .expect("write generated release");
    let machine = env::var("CARGO_CFG_TARGET_ARCH").expect("target machine");
    fs::write(
        generated.join("compile.h"),
        format!(
            concat!(
                "#define UTS_MACHINE {:?}\n",
                "#define UTS_VERSION \"#1 Stela\"\n",
                "#define LINUX_COMPILE_BY \"stela\"\n",
                "#define LINUX_COMPILE_HOST \"build\"\n",
                "#define LINUX_COMPILER __VERSION__\n",
            ),
            machine
        ),
    )
    .expect("write generated compile identity");
    root
}

impl Linux {
    pub fn new() -> Self {
        require_sources();
        let environment = stela_c_build::linux::Environment::new(stela_c_build::linux::Roots {
            linux: LINUX.into(),
            compat: COMPAT.into(),
            output: out_dir(),
        });
        let mut linux = Self {
            environment,
            hosted: Vec::new(),
            captured: Vec::new(),
        };
        let kernel = sources(&format!("{COMPAT}/kernel"));
        let crc_tables = linux_crc::tables();
        // Unchanged shared helpers use Linux's arithmetic types. Stela's
        // extra conversion diagnostics remain confined to its own source.
        let upstream = vec![
            PathBuf::from(format!("{LINUX}/init/init_task.c")),
            PathBuf::from(format!("{LINUX}/init/version-timestamp.c")),
            PathBuf::from(format!("{LINUX}/mm/init-mm.c")),
            PathBuf::from(format!("{LINUX}/mm/list_lru.c")),
            PathBuf::from(format!("{LINUX}/mm/oom_adj.c")),
            PathBuf::from(format!("{LINUX}/mm/mmap_boot.c")),
            PathBuf::from(format!("{LINUX}/mm/vma_init.c")),
            PathBuf::from(format!("{LINUX}/mm/vmstat_init.c")),
            PathBuf::from(format!("{LINUX}/mm/pagecache_init.c")),
            PathBuf::from(format!("{LINUX}/mm/folio_wait.c")),
            PathBuf::from(format!("{LINUX}/mm/folio_fs.c")),
            PathBuf::from(format!("{LINUX}/mm/filemap_batch.c")),
            PathBuf::from(format!("{LINUX}/mm/filemap_mmap.c")),
            PathBuf::from(format!("{LINUX}/mm/filemap_mkwrite.c")),
            PathBuf::from(format!("{LINUX}/mm/readahead.c")),
            PathBuf::from(format!("{LINUX}/mm/fadvise.c")),
            PathBuf::from(format!("{LINUX}/mm/user_prefault.c")),
            PathBuf::from(format!("{LINUX}/mm/lruvec.c")),
            PathBuf::from(format!("{LINUX}/mm/mlock_batch.c")),
            PathBuf::from(format!("{LINUX}/mm/swap.c")),
            PathBuf::from(format!("{LINUX}/mm/shrinker.c")),
            PathBuf::from(format!("{LINUX}/mm/reclaim_throttle.c")),
            PathBuf::from(format!("{LINUX}/mm/workingset.c")),
            PathBuf::from(format!("{LINUX}/mm/oom_victim.c")),
            PathBuf::from(format!("{LINUX}/mm/page-writeback.c")),
            PathBuf::from(format!("{LINUX}/mm/writeback_domain.c")),
            PathBuf::from(format!("{LINUX}/mm/writeback_folio.c")),
            PathBuf::from(format!("{LINUX}/mm/backing-dev-inode.c")),
            PathBuf::from(format!("{LINUX}/kernel/pid.c")),
            PathBuf::from(format!("{LINUX}/kernel/task_rcu.c")),
            PathBuf::from(format!("{LINUX}/kernel/task_work.c")),
            PathBuf::from(format!("{LINUX}/kernel/fork.c")),
            PathBuf::from(format!("{LINUX}/kernel/fork_caches.c")),
            PathBuf::from(format!("{LINUX}/kernel/fork_task.c")),
            PathBuf::from(format!("{LINUX}/kernel/fork_stack.c")),
            PathBuf::from(format!("{LINUX}/kernel/fork_release.c")),
            PathBuf::from(format!("{LINUX}/kernel/fork_mm.c")),
            PathBuf::from(format!("{LINUX}/kernel/nsproxy.c")),
            PathBuf::from(format!("{LINUX}/kernel/nscommon.c")),
            PathBuf::from(format!("{LINUX}/kernel/nstree.c")),
            PathBuf::from(format!("{LINUX}/kernel/ucount.c")),
            PathBuf::from(format!("{LINUX}/kernel/cred.c")),
            PathBuf::from(format!("{LINUX}/kernel/ptrace_access.c")),
            PathBuf::from(format!("{LINUX}/security/commoncap_ptrace.c")),
            PathBuf::from(format!("{LINUX}/kernel/signal_state.c")),
            PathBuf::from(format!("{LINUX}/kernel/restart_no_syscall.c")),
            PathBuf::from(format!("{LINUX}/kernel/task_rusage.c")),
            PathBuf::from(format!("{LINUX}/kernel/task_exit.c")),
            PathBuf::from(format!("{LINUX}/kernel/task_wait.c")),
            PathBuf::from(format!("{LINUX}/fs/fs_struct.c")),
            PathBuf::from(format!("{LINUX}/fs/init_fdtable.c")),
            PathBuf::from(format!("{LINUX}/fs/file_ref.c")),
            PathBuf::from(format!("{LINUX}/fs/file.c")),
            PathBuf::from(format!("{LINUX}/fs/simple_xattr.c")),
            PathBuf::from(format!("{LINUX}/fs/xattr_access.c")),
            PathBuf::from(format!("{LINUX}/fs/pseudo_metadata.c")),
            PathBuf::from(format!("{LINUX}/fs/stashed_path.c")),
            PathBuf::from(format!("{LINUX}/fs/mount_cache.c")),
            PathBuf::from(format!("{LINUX}/fs/mnt_idmapping.c")),
            PathBuf::from(format!("{LINUX}/drivers/base/map.c")),
            PathBuf::from(format!("{LINUX}/drivers/base/property.c")),
            PathBuf::from(format!("{LINUX}/fs/char_dev.c")),
            PathBuf::from(format!("{LINUX}/fs/d_path.c")),
            PathBuf::from(format!("{LINUX}/fs/dcache.c")),
            PathBuf::from(format!("{LINUX}/fs/dcache_init.c")),
            PathBuf::from(format!("{LINUX}/fs/dentry_ancestry.c")),
            PathBuf::from(format!("{LINUX}/fs/pnode.c")),
            PathBuf::from(format!("{LINUX}/fs/file_table_init.c")),
            PathBuf::from(format!("{LINUX}/fs/file_async.c")),
            PathBuf::from(format!("{LINUX}/fs/pipe_buffers.c")),
            PathBuf::from(format!("{LINUX}/fs/pipe.c")),
            PathBuf::from(format!("{LINUX}/fs/splice_file.c")),
            PathBuf::from(format!("{LINUX}/fs/filesystems.c")),
            PathBuf::from(format!("{LINUX}/fs/fs_context.c")),
            PathBuf::from(format!("{LINUX}/fs/fs_context_log.c")),
            PathBuf::from(format!("{LINUX}/fs/fs_context_params.c")),
            PathBuf::from(format!("{LINUX}/fs/fs_pin.c")),
            PathBuf::from(format!("{LINUX}/fs/fs_parser.c")),
            PathBuf::from(format!("{LINUX}/fs/super_anon_dev.c")),
            PathBuf::from(format!("{LINUX}/fs/super_lifetime.c")),
            PathBuf::from(format!("{LINUX}/fs/inode_cache_init.c")),
            PathBuf::from(format!("{LINUX}/fs/inode_timestamps.c")),
            PathBuf::from(format!("{LINUX}/fs/bad_inode_ops.c")),
            PathBuf::from(format!("{LINUX}/fs/inode_evict.c")),
            PathBuf::from(format!("{LINUX}/fs/attr.c")),
            PathBuf::from(format!("{LINUX}/fs/name_hash.c")),
            PathBuf::from(format!("{LINUX}/fs/path_get.c")),
            PathBuf::from(format!("{LINUX}/fs/pidfs_metadata.c")),
            PathBuf::from(format!("{LINUX}/fs/pidfs.c")),
            PathBuf::from(format!("{LINUX}/fs/filename.c")),
            PathBuf::from(format!("{LINUX}/fs/filp_close.c")),
            PathBuf::from(format!("{LINUX}/fs/path_open.c")),
            PathBuf::from(format!("{LINUX}/fs/file_position.c")),
            PathBuf::from(format!("{LINUX}/fs/fs_dirent.c")),
            PathBuf::from(format!("{LINUX}/fs/libfs.c")),
            PathBuf::from(format!("{LINUX}/fs/namei.c")),
            PathBuf::from(format!("{LINUX}/fs/namespace_tree.c")),
            PathBuf::from(format!("{LINUX}/fs/mount_init.c")),
            PathBuf::from(format!("{LINUX}/init/rootfs.c")),
            PathBuf::from(format!("{LINUX}/mm/shmem_mount.c")),
            PathBuf::from(format!("{LINUX}/fs/ramfs/inode.c")),
            PathBuf::from(format!("{LINUX}/fs/ramfs/file-mmu.c")),
            PathBuf::from(format!("{LINUX}/fs/nullfs.c")),
            PathBuf::from(format!("{LINUX}/fs/nsfs.c")),
            PathBuf::from(format!("{LINUX}/lib/string.c")),
            PathBuf::from(format!("{LINUX}/lib/hexdump.c")),
            PathBuf::from(format!("{LINUX}/lib/string_unescape.c")),
            PathBuf::from(format!("{LINUX}/lib/errseq.c")),
            PathBuf::from(format!("{LINUX}/lib/math/div64.c")),
            PathBuf::from(format!("{LINUX}/lib/crypto/blake2s.c")),
            PathBuf::from(format!("{LINUX}/lib/iov_iter_copy.c")),
            PathBuf::from(format!("{LINUX}/lib/ratelimit.c")),
            PathBuf::from(format!("{LINUX}/drivers/i2c/algos/i2c-algo-bit.c")),
            PathBuf::from(format!("{LINUX}/lib/scatterlist.c")),
            PathBuf::from(format!("{LINUX}/lib/find_bit.c")),
            PathBuf::from(format!("{LINUX}/lib/bitmap.c")),
            PathBuf::from(format!("{LINUX}/lib/bitmap-parse.c")),
            PathBuf::from(format!("{LINUX}/lib/kstrtox-parse.c")),
            PathBuf::from(format!("{LINUX}/lib/idr.c")),
            PathBuf::from(format!("{LINUX}/lib/radix-tree.c")),
            PathBuf::from(format!("{LINUX}/lib/xarray.c")),
            PathBuf::from(format!("{LINUX}/lib/rbtree.c")),
            PathBuf::from(format!("{LINUX}/lib/rhashtable.c")),
            PathBuf::from(format!("{LINUX}/lib/timerqueue.c")),
            PathBuf::from(format!("{LINUX}/kernel/time/timer_round.c")),
            PathBuf::from(format!("{LINUX}/kernel/time/clock_ticks.c")),
            PathBuf::from(format!("{LINUX}/lib/kobject.c")),
            PathBuf::from(format!("{LINUX}/lib/plist.c")),
            PathBuf::from(format!("{LINUX}/lib/kobject_uevent.c")),
            PathBuf::from(format!("{LINUX}/lib/ctype.c")),
            PathBuf::from(format!("{LINUX}/lib/refcount_lock.c")),
            PathBuf::from(format!("{LINUX}/lib/lockref.c")),
            PathBuf::from(format!("{LINUX}/lib/is_single_threaded.c")),
            PathBuf::from(format!("{LINUX}/lib/rcuref.c")),
            PathBuf::from(format!("{LINUX}/lib/flex_proportions.c")),
            PathBuf::from(format!("{LINUX}/kernel/user.c")),
            // kthread_mm.c needs the native Linux address-space switch and TLB
            // owners. The kernel-only mount selects the thread helpers.
            PathBuf::from(format!("{LINUX}/kernel/kthread.c")),
            PathBuf::from(format!("{LINUX}/kernel/workqueue.c")),
            PathBuf::from(format!("{LINUX}/kernel/exec_state.c")),
            PathBuf::from(format!("{LINUX}/kernel/softirq.c")),
            PathBuf::from(format!("{LINUX}/kernel/cpu_topology.c")),
            PathBuf::from(format!("{LINUX}/mm/page_alloc_state.c")),
            PathBuf::from(format!("{LINUX}/kernel/rcu/tiny.c")),
            PathBuf::from(format!("{LINUX}/kernel/rcu/sync.c")),
            PathBuf::from(format!("{LINUX}/kernel/rcu/update.c")),
            PathBuf::from(format!("{LINUX}/kernel/smpboot.c")),
            PathBuf::from(format!("{LINUX}/kernel/rcu/srcutiny.c")),
            PathBuf::from(format!("{LINUX}/kernel/rcu/wakeme.c")),
            PathBuf::from(format!("{LINUX}/kernel/locking/mutex.c")),
            PathBuf::from(format!("{LINUX}/kernel/locking/percpu-rwsem.c")),
            PathBuf::from(format!("{LINUX}/kernel/locking/rtmutex_api.c")),
            PathBuf::from(format!("{LINUX}/kernel/sched/capacity_state.c")),
            PathBuf::from(format!("{LINUX}/kernel/sched/fork_load.c")),
            PathBuf::from(format!("{LINUX}/kernel/sched/fork_support.c")),
            PathBuf::from(format!("{LINUX}/kernel/sched/deadline.c")),
            PathBuf::from(format!("{LINUX}/kernel/sched/rt.c")),
            PathBuf::from(format!("{LINUX}/kernel/sched/pelt.c")),
            PathBuf::from(format!("{LINUX}/kernel/sched/rt_timeslice.c")),
            PathBuf::from(format!("{LINUX}/kernel/sched/rq_lock.c")),
            PathBuf::from(format!("{LINUX}/kernel/sched/rq_clock.c")),
            PathBuf::from(format!("{LINUX}/kernel/sched/rq_resched.c")),
            PathBuf::from(format!("{LINUX}/kernel/sched/rq_tasks.c")),
            PathBuf::from(format!("{LINUX}/kernel/sched/rq_root.c")),
            PathBuf::from(format!("{LINUX}/kernel/sched/rq_class.c")),
            PathBuf::from(format!("{LINUX}/kernel/sched/cpudeadline.c")),
            PathBuf::from(format!("{LINUX}/kernel/sched/cpupri.c")),
            PathBuf::from(format!("{LINUX}/kernel/sched/sched_ratio.c")),
            PathBuf::from(format!("{LINUX}/kernel/sched/rq_debug.c")),
            PathBuf::from(format!("{LINUX}/kernel/sched/rq_migration.c")),
            PathBuf::from(format!("{LINUX}/kernel/sched/clock.c")),
            PathBuf::from(format!("{LINUX}/kernel/sched/fork_metadata.c")),
            PathBuf::from(format!("{LINUX}/kernel/sched/cputime_group.c")),
            PathBuf::from(format!("{LINUX}/kernel/sched/user_affinity.c")),
            PathBuf::from(format!("{LINUX}/kernel/sched/wait_support.c")),
            PathBuf::from(format!("{LINUX}/kernel/sched/wait.c")),
            PathBuf::from(format!("{LINUX}/kernel/sched/swait.c")),
            PathBuf::from(format!("{LINUX}/kernel/sched/completion.c")),
            PathBuf::from(format!("{LINUX}/kernel/rcuwait_wake.c")),
            PathBuf::from(format!("{LINUX}/kernel/rcu/rcuwait_finish.c")),
            PathBuf::from(format!("{LINUX}/fs/seq_output.c")),
            PathBuf::from(format!("{LINUX}/fs/seq_path.c")),
            PathBuf::from(format!("{LINUX}/fs/seq_lifetime.c")),
            PathBuf::from(format!("{LINUX}/fs/task_comm.c")),
            PathBuf::from(format!("{LINUX}/lib/maple_tree.c")),
        ];
        let mut upstream = upstream;
        if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("uefi") {
            upstream.push(PathBuf::from(format!(
                "{LINUX}/kernel/sched/sched_class_bounds.c"
            )));
        }
        upstream.extend(
            DMA_BUF_SOURCES
                .iter()
                .map(|source| PathBuf::from(format!("{LINUX}/drivers/dma-buf/{source}.c"))),
        );
        let hosted_upstream = upstream.clone();
        println!("cargo:rerun-if-changed={LINUX}/kernel/sched");
        upstream.retain(|source| !captured_units().iter().any(|unit| unit.path() == *source));
        for source in &upstream {
            println!("cargo:rerun-if-changed={}", source.display());
        }
        let uts = initial_uts_headers();
        let mut build = configure();
        linux.environment.apply(&mut build, Some(&uts), &[], None);
        // The ownership adapters consume private declarations from the same
        // pinned kernel tree, including RCU phases and workqueue metadata.
        build.flag("-isystem").flag(Path::new(LINUX).join("kernel"));
        let crc_objects = linux_crc::objects(&build, &crc_tables);
        build.objects(crc_objects);
        {
            // Match the independently reviewed common-cohort command. The
            // generated UTS metadata and private kernel headers belong only
            // to the uncaptured original providers and ownership adapters.
            let mut common_build = configure();
            linux.environment.apply(&mut common_build, None, &[], None);
            let mut captured_build = upstream_build(&common_build, Path::new(COMPAT));
            upstream_warnings(&mut captured_build);
            for spec in COMMON {
                let unit = Unit::from(*spec);
                let compiler = linux_capture::compiler(&captured_build);
                let placement = linux_capture::Placement::new(
                    &unit.path(),
                    &out_dir(),
                    &[
                        Path::new("../.."),
                        compiler.parent().expect("compiler root"),
                    ],
                )
                .expect("common source placement");
                linux.captured.push(linux_capture::compile(
                    &captured_build,
                    &Path::new(COMPAT).join("stela/registration.h"),
                    *spec,
                    &placement,
                ));
            }
            let image = linux_capture::source(
                &linux.captured,
                Projection {
                    symbol: "stela_linux_common_image",
                    expected: COMMON,
                    imported_units: 0,
                    descriptors_only: true,
                },
            );
            let descriptors = build.clone().file(image).compile_intermediates();
            build.objects(descriptors);
            let digest =
                linux_capture::write(&out_dir().join("captured-units.bin"), &linux.captured);
            println!("cargo:cohort_sha256={digest}");
            build.objects(linux.captured.iter().map(|unit| unit.object()));
        }
        if super::task_fixtures() && env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux") {
            build.define("STELA_LINUX_REGISTRY_SOURCE_TEST", None);
            build.define("STELA_LINUX_HOSTED_PAGE_TEST", None);
            build.define("STELA_LINUX_CACHE_SOURCE_TEST", None);
            // Fixture code shares archive members with the services it
            // tests and calls the hosted harness (`stela/test.h`).
            println!("cargo:hosted_fixtures=1");
        }
        linux_archive(&build, "stela-linux", &kernel, &upstream, Path::new(COMPAT));
        // A callable target-ABI fixture plus host helpers only. It links the
        // SAME production common archive/Rust heap as the unit binary;
        // never mix duplicate native/hosted common archives. The standalone
        // C suites below keep their separate sanitizer-linked programs.
        if super::task_fixtures() {
            let mut helper = stela_c_build::native::compiler();
            helper.define("STELA_TEST_CANONICAL_RUST_HEAP", None);
            helper.file(format!("{COMPAT}/stela/test.c"));
            let helper_objects = helper.compile_intermediates();
            let mut fixture = configure();
            linux.environment.apply(&mut fixture, None, &[], None);
            if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux") {
                fixture
                    .define("STELA_LINUX_DEFERRED_FREE_SOURCE_TEST", None)
                    .define("STELA_LINUX_RESOURCES_SOURCE_TEST", None)
                    .files([
                        format!("{COMPAT}/stela/deferred_free_test.c"),
                        format!("{COMPAT}/stela/resources_test.c"),
                    ]);
                for symbol in DEFERRED_FREE_OBSERVERS {
                    println!("cargo:rustc-link-arg-tests=-Wl,--wrap={symbol}");
                }
            }
            fixture
                .define("STELA_LINUX_TREES_TEST", None)
                .files([
                    format!("{COMPAT}/kernel/trees.c"),
                    format!("{COMPAT}/stela/percpu_test.c"),
                    format!("{COMPAT}/stela/task_test.c"),
                    format!("{COMPAT}/stela/atomic_callback_test.c"),
                    format!("{COMPAT}/stela/mutex_test.c"),
                    format!("{COMPAT}/stela/rtmutex_test.c"),
                    format!("{COMPAT}/stela/resource_test.c"),
                    format!("{COMPAT}/stela/timer_test.c"),
                    format!("{COMPAT}/stela/workqueue_test.c"),
                    format!("{COMPAT}/stela/i2c_test.c"),
                    format!("{COMPAT}/stela/sync_test.c"),
                    format!("{COMPAT}/stela/srcu_test.c"),
                    format!("{COMPAT}/stela/rcu_original_test.c"),
                ])
                .objects(helper_objects)
                .compile("linux-task-fixture");
        }
        if let Some(host) = hosted() {
            let services = [
                PathBuf::from(format!("{COMPAT}/stela/test.c")),
                PathBuf::from(format!("{COMPAT}/stela/registry_test_host.c")),
                PathBuf::from(format!("{COMPAT}/stela/taint_test_host.c")),
                PathBuf::from(format!("{COMPAT}/stela/rodata_test_host.c")),
            ];
            let services = archive(&host, "linux-host", &services);
            let mut kernel_build = host;
            linux
                .environment
                .apply(&mut kernel_build, Some(&uts), &[], None);
            kernel_build
                .flag("-isystem")
                .flag(Path::new(LINUX).join("kernel"))
                // ASan calls libc's two-argument getrusage. The embedded
                // kernel helper takes a task and must never satisfy that call.
                .define("getrusage", "stela_linux_hosted_getrusage");
            let crc_objects = linux_crc::objects(&kernel_build, &crc_tables);
            kernel_build.objects(crc_objects);
            let mut hosted_kernel = kernel;
            hosted_kernel.push(PathBuf::from(format!(
                "{COMPAT}/stela/native_callback_test_host.c"
            )));
            linux.hosted = vec![
                linux_archive(
                    &kernel_build,
                    "linux-hosted",
                    &hosted_kernel,
                    &hosted_upstream,
                    Path::new(COMPAT),
                ),
                services,
            ];
        }
        linux
    }

    pub fn tests(&self, tests: &mut Tests) {
        if super::task_fixtures() {
            tests.rust_children();
        }
        let Some(mut build) = hosted() else {
            return;
        };
        self.environment.apply(&mut build, None, &[], None);
        build.flag("-isystem").flag(Path::new(LINUX).join("kernel"));
        let archives = self.hosted.iter().map(PathBuf::as_path).collect::<Vec<_>>();
        // Dedicated lifecycle fixture: unchanged original kobject/uevent APIs.
        tests.add(
            &build,
            "linux_kobjects",
            &format!("{COMPAT}/stela/kobject_test.c"),
            &archives,
        );
        for (name, source) in [
            ("linux_compiler_abi", "abi_test.c"),
            ("linux_thread_initializers", "thread_initializers_test.c"),
            ("linux_acpi_client", "acpi_client_test.c"),
            ("linux_acpi_dsm", "acpi_dsm_test.c"),
            ("linux_random", "random_test.c"),
            ("linux_resources", "resources_test.c"),
            ("linux_seq_output", "seq_output_test.c"),
        ] {
            tests.add(&build, name, &format!("{COMPAT}/stela/{source}"), &archives);
        }
        // This fixture observes calls with the ELF linker's --wrap.
        if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux") {
            let mut deferred = build.clone();
            for symbol in DEFERRED_FREE_OBSERVERS {
                deferred.flag(format!("-Wl,--wrap={symbol}"));
            }
            tests.add(
                &deferred,
                "linux_deferred_free",
                &format!("{COMPAT}/stela/deferred_free_test.c"),
                &archives,
            );
        }
        if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux") {
            let mut writeback = build.clone();
            writeback.flag("-Wl,--wrap=stela_linux_current");
            tests.add(
                &writeback,
                "linux_writeback_init",
                &format!("{COMPAT}/stela/writeback_init_test.c"),
                &archives,
            );
        }
        // These component fixtures use init_task credentials without a native
        // task lease. Only their ELF links wrap current.
        if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux") {
            for (name, source, define) in [
                ("linux_file", "file.c", "STELA_LINUX_FILE_TEST"),
                ("linux_mapping", "mapping.c", "STELA_LINUX_MAPPING_TEST"),
            ] {
                let mut fixture = build.clone();
                fixture
                    .define(define, None)
                    .flag("-Wl,--wrap=stela_linux_current");
                if name == "linux_file" {
                    for symbol in [
                        "__cond_resched",
                        "call_rcu",
                        "queue_work_on",
                        "synchronize_rcu",
                    ] {
                        fixture.flag(format!("-Wl,--wrap={symbol}"));
                    }
                }
                tests.add(
                    &fixture,
                    name,
                    &format!("{COMPAT}/kernel/{source}"),
                    &archives,
                );
            }
        }
        for (name, source, define) in [
            ("linux_printk", "printk.c", "STELA_LINUX_PRINTK_TEST"),
            ("linux_panic", "panic.c", "STELA_LINUX_PANIC_TEST"),
            ("linux_pages", "page.c", "STELA_LINUX_PAGE_TEST"),
            ("linux_slab", "slab.c", "STELA_LINUX_SLAB_TEST"),
            ("linux_params", "params.c", "STELA_LINUX_PARAMS_TEST"),
            (
                "linux_params_parser",
                "params.c",
                "STELA_LINUX_PARAMS_PARSER_TEST",
            ),
            ("linux_registry", "registry.c", "STELA_LINUX_REGISTRY_TEST"),
            ("linux_taint", "taint.c", "STELA_LINUX_TAINT_TEST"),
            (
                "linux_entry_generation",
                "linux.c",
                "STELA_LINUX_ENTRY_GENERATION_TEST",
            ),
            ("linux_firmware", "firmware.c", "STELA_LINUX_FIRMWARE_TEST"),
            ("linux_crc", "crc.c", "STELA_LINUX_CRC_TEST"),
            ("linux_find_bit", "find_bit.c", "STELA_LINUX_FIND_BIT_TEST"),
            ("linux_cpuhotplug", "cpuhotplug.c", "STELA_LINUX_CPUHP_TEST"),
            (
                "linux_string_helpers",
                "string_helpers.c",
                "STELA_LINUX_STRING_HELPERS_TEST",
            ),
            ("linux_printf", "printf.c", "STELA_LINUX_PRINTF_TEST"),
            ("linux_uuid", "uuid.c", "STELA_LINUX_UUID_TEST"),
            ("linux_kstrtox", "kstrtox.c", "STELA_LINUX_KSTRTOX_TEST"),
            ("linux_jiffies", "jiffies.c", "STELA_LINUX_JIFFIES_TEST"),
            ("linux_device", "device.c", "STELA_LINUX_DEVICE_TEST"),
            (
                "linux_device_catalogue",
                "catalogue.c",
                "STELA_LINUX_CATALOGUE_TEST",
            ),
            (
                "linux_device_catalogue_legacy",
                "catalogue.c",
                "STELA_LINUX_CATALOGUE_LEGACY_TEST",
            ),
            (
                "linux_device_catalogue_task",
                "catalogue.c",
                "STELA_LINUX_CATALOGUE_TASK_TEST",
            ),
            (
                "linux_device_catalogue_workqueue",
                "catalogue.c",
                "STELA_LINUX_CATALOGUE_WORKQUEUE_TEST",
            ),
            ("linux_reclaim", "reclaim.c", "STELA_LINUX_RECLAIM_TEST"),
            ("linux_sort", "sort.c", "STELA_LINUX_SORT_TEST"),
            ("linux_usercopy", "usercopy.c", "STELA_LINUX_USERCOPY_TEST"),
            ("linux_dma", "dma.c", "STELA_LINUX_DMA_TEST"),
            ("linux_pci", "pci.c", "STELA_LINUX_PCI_TEST"),
            ("linux_pci_host", "pci_host.c", "STELA_LINUX_PCI_HOST_TEST"),
            ("linux_service", "service.c", "STELA_LINUX_SERVICE_TEST"),
            ("linux_vmalloc", "vmalloc.c", "STELA_LINUX_VMALLOC_TEST"),
            ("linux_refcount", "refcount.c", "STELA_LINUX_REFCOUNT_TEST"),
            (
                "linux_const_string",
                "const_string.c",
                "STELA_LINUX_CONST_STRING_TEST",
            ),
        ] {
            let mut build = build.clone();
            build.define(define, None);
            tests.add(
                &build,
                name,
                &format!("{COMPAT}/kernel/{source}"),
                &archives,
            );
        }
    }
}

const DEFERRED_FREE_OBSERVERS: [&str; 3] = [
    "stela_linux_heap_alloc",
    "stela_linux_heap_free",
    "call_rcu",
];

/// Generic kernel registrations precede every class's registrations in the
/// canonical image, retaining one definition of their descriptor globals.
fn captured_units() -> Vec<Unit> {
    COMMON.iter().copied().map(Unit::from).collect()
}
