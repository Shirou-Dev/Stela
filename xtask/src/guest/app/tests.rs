use super::*;
use sha2::{Digest, Sha256};
use std::{io::Read as _, os::unix::fs::symlink, time::Duration};

const VERSION: &str = "0.1.0";
/// A file name that, under `/System/Volumes/Data/Applications/Stela.app/Contents/Resources/`, passes 255 bytes.
const KERNEL_PATH_BYTES_FOR_TEST: usize = 220;

/// A thin arm64 executable around `code`, ad-hoc signed as `codesign`
/// signs an app: a SHA-256 code directory naming `identifier`, with the
/// hashes of `info` and `resources` in their special slots.
fn executable(cpu: u32, identifier: &str, code: &[u8], info: &[u8], resources: &[u8]) -> Vec<u8> {
    let mut file = Vec::new();
    for word in [0xfeed_facf_u32, cpu, 0, 2, 1, 16, 0, 0] {
        file.extend(word.to_le_bytes());
    }
    let offset = (48 + code.len()).next_multiple_of(16);
    let mut directory = Vec::new();
    let name = [identifier.as_bytes(), &[0]].concat();
    let special = 5;
    let hashes = 48 + name.len() + special * 32;
    let pages = offset.div_ceil(4096);
    let length = hashes + pages * 32;
    for word in [0x1d_u32, 16, offset as u32, 20 + length as u32] {
        file.extend(word.to_le_bytes());
    }
    file.extend(code);
    file.resize(offset, 0);
    for word in [
        0xfade_0c02_u32,
        length as u32,
        0x20100,
        2,
        hashes as u32,
        48,
        special as u32,
        pages as u32,
        offset as u32,
    ] {
        directory.extend(word.to_be_bytes());
    }
    directory.extend([32, 2, 0, 12, 0, 0, 0, 0, 0, 0, 0, 0]);
    directory.extend(&name);
    for slot in (1..=special).rev() {
        match slot {
            1 => directory.extend(Sha256::digest(info)),
            3 => directory.extend(Sha256::digest(resources)),
            _ => directory.extend([0; 32]),
        }
    }
    for page in file.chunks(4096) {
        directory.extend(Sha256::digest(page));
    }
    let mut blob = Vec::new();
    for word in [0xfade_0cc0_u32, 20 + directory.len() as u32, 1, 0, 20] {
        blob.extend(word.to_be_bytes());
    }
    blob.extend(directory);
    file.extend(blob);
    file
}

fn xml(value: plist::Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    plist::to_writer_xml(&mut bytes, &value).unwrap();
    bytes
}

/// Writes a signed Stela.app with one resource under `root`.
fn app(root: &Path, identifier: &str) -> PathBuf {
    let app = root.join("Stela.app");
    let contents = app.join("Contents");
    for directory in ["MacOS", "Resources", "_CodeSignature"] {
        fs::create_dir_all(contents.join(directory)).unwrap();
    }
    let mut info = plist::Dictionary::new();
    for (key, value) in [
        ("CFBundleIdentifier", identifier),
        ("CFBundleExecutable", "Stela"),
        ("CFBundleShortVersionString", VERSION),
        ("StelaSourceRevision", "0123456789ab-modified"),
    ] {
        info.insert(key.into(), value.into());
    }
    let info = xml(info.into());
    let icon = b"icon bytes".to_vec();
    let mut sealed = plist::Dictionary::new();
    let mut entry = plist::Dictionary::new();
    entry.insert(
        "hash2".into(),
        plist::Value::Data(Sha256::digest(&icon).to_vec()),
    );
    sealed.insert("Resources/Stela.icns".into(), entry.into());
    let mut seal = plist::Dictionary::new();
    seal.insert("files2".into(), sealed.into());
    let resources = xml(seal.into());
    let code = executable(
        object::macho::CPU_TYPE_ARM64,
        identifier,
        &[0xc0, 0x03, 0x5f, 0xd6].repeat(1500),
        &info,
        &resources,
    );
    fs::write(contents.join("Info.plist"), info).unwrap();
    fs::write(contents.join("Resources/Stela.icns"), icon).unwrap();
    fs::write(contents.join("_CodeSignature/CodeResources"), resources).unwrap();
    fs::write(contents.join("MacOS/Stela"), code).unwrap();
    app
}

fn refusal(app: &Path) -> String {
    format!(
        "{:#}",
        Package::read(app).err().expect("the package is refused")
    )
}

#[test]
fn a_signed_app_is_archived_with_its_modes_and_bytes() {
    let root = tempfile::tempdir().unwrap();
    let app = app(root.path(), IDENTIFIER);
    let package = Package::read(&app).unwrap();
    assert_eq!(package.version, VERSION);
    assert_eq!(package.revision, "0123456789ab-modified");
    let archive = package.archive().unwrap();
    assert_eq!(
        archive,
        package.archive().unwrap(),
        "the archive is reproducible"
    );
    let mut zip = zip::ZipArchive::new(Cursor::new(archive)).unwrap();
    let names: Vec<_> = zip.file_names().map(str::to_owned).collect();
    assert_eq!(
        names,
        [
            "Stela.app/",
            "Stela.app/Contents/",
            "Stela.app/Contents/MacOS/",
            "Stela.app/Contents/Resources/",
            "Stela.app/Contents/_CodeSignature/",
            "Stela.app/Contents/Info.plist",
            "Stela.app/Contents/MacOS/Stela",
            "Stela.app/Contents/Resources/Stela.icns",
            "Stela.app/Contents/_CodeSignature/CodeResources",
        ]
    );
    for name in names {
        let mut entry = zip.by_name(&name).unwrap();
        let mode = entry.unix_mode().unwrap() & 0o777;
        let executable = name.ends_with('/') || name.ends_with("MacOS/Stela");
        assert_eq!(mode, if executable { 0o755 } else { 0o644 }, "{name}");
        if !name.ends_with('/') {
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes).unwrap();
            assert_eq!(bytes, fs::read(root.path().join(&name)).unwrap(), "{name}");
        }
    }
}

#[test]
fn the_header_names_the_payload_and_where_the_kext_stages_it() {
    let root = tempfile::tempdir().unwrap();
    let package = Package::read(&app(root.path(), IDENTIFIER)).unwrap();
    let header = package.header().unwrap();
    for line in [
        "#define STELA_APP_PRESENT 1\n",
        "#define STELA_APP_IDENTIFIER \"org.stela.Stela\"\n",
        "#define STELA_APP_VERSION \"0.1.0\"\n",
        "#define STELA_APP_REVISION \"0123456789ab-modified\"\n",
        "#define STELA_APP_PATH \"/System/Volumes/Data/Applications/Stela.app\"\n",
        "#define STELA_APP_ARCHIVE_PATH \"/System/Volumes/Data/private/var/db/org.stela.Stela.zip\"\n",
        "#define STELA_APP_JOB_PATH \"/System/Volumes/Data/Library/LaunchDaemons/org.stela.Stela.install.plist\"\n",
        "static const unsigned char stela_app_archive[] = {\n\t80,75,3,4,",
        "static const unsigned char stela_app_job[] = {\n\t60,63,120,109,108,",
    ] {
        assert!(header.contains(line), "{line}");
    }
    // SHA-256("icon bytes") is 10 bytes long and its digest is the seal's.
    let icon = format!(
        "\t{{\"Contents/Resources/Stela.icns\", {{{}}}, 10}},\n",
        c_digest(b"icon bytes")
    );
    assert!(header.contains(&icon));
    assert!(absent_header().contains("#define STELA_APP_PRESENT 0\n"));
}

#[test]
fn a_bundle_its_signature_does_not_seal_is_refused() {
    let root = tempfile::tempdir().unwrap();
    let app = app(root.path(), IDENTIFIER);
    let resources = app.join("Contents/Resources");
    fs::write(resources.join("._Stela.icns"), b"metadata").unwrap();
    assert!(refusal(&app).contains("Contents/Resources/._Stela.icns is not sealed"));
    fs::remove_file(resources.join("._Stela.icns")).unwrap();
    let long = "x".repeat(KERNEL_PATH_BYTES_FOR_TEST);
    fs::write(resources.join(&long), b"x").unwrap();
    assert!(refusal(&app).contains("longer than the kext's 256-byte paths"));
    fs::remove_file(resources.join(&long)).unwrap();
    fs::write(resources.join("Stela.icns"), b"other bytes").unwrap();
    assert!(refusal(&app).contains("differs from its seal"));
    fs::write(resources.join("Stela.icns"), b"icon bytes").unwrap();
    symlink("Stela.icns", resources.join("link")).unwrap();
    assert!(refusal(&app).contains("neither a file nor a directory"));
    fs::remove_file(resources.join("link")).unwrap();
    fs::remove_file(resources.join("Stela.icns")).unwrap();
    assert!(refusal(&app).contains("sealed but absent"));
    fs::write(resources.join("Stela.icns"), b"icon bytes").unwrap();
    Package::read(&app).unwrap();
    let executable = app.join("Contents/MacOS/Stela");
    let mut code = fs::read(&executable).unwrap();
    code[100] ^= 1;
    fs::write(&executable, &code).unwrap();
    assert!(refusal(&app).contains("code page 0 differs"));
    code[100] ^= 1;
    fs::write(&executable, &code).unwrap();
    let info = app.join("Contents/Info.plist");
    let text = fs::read_to_string(&info).unwrap();
    fs::write(&info, text.replace("0.1.0", "0.1.1")).unwrap();
    assert!(refusal(&app).contains("Info.plist differs from the executable's signature"));
}

#[test]
fn only_stela_app_for_arm64_is_embedded() {
    let root = tempfile::tempdir().unwrap();
    let other = app(root.path(), "com.example.Other");
    assert!(refusal(&other).contains("not Stela.app"));
    let root = tempfile::tempdir().unwrap();
    let app = app(root.path(), IDENTIFIER);
    let read = |name: &str| fs::read(app.join("Contents").join(name)).unwrap();
    let intel = executable(
        object::macho::CPU_TYPE_X86_64,
        IDENTIFIER,
        b"code",
        &read("Info.plist"),
        &read("_CodeSignature/CodeResources"),
    );
    fs::write(app.join("Contents/MacOS/Stela"), intel).unwrap();
    assert!(refusal(&app).contains("no arm64 code"));
}

#[test]
fn versions_and_plist_strings_are_read_as_the_kext_reads_them() {
    for good in ["0", "0.1.0", "1.2.3.4", "999999999"] {
        assert!(is_version(good), "{good}");
    }
    for bad in [
        "",
        "1.",
        ".1",
        "1..2",
        "1.2.3.4.5",
        "1.0-beta",
        "1234567890",
    ] {
        assert!(!is_version(bad), "{bad}");
    }
    let text = b"<dict><key>A</key>\n\t<string>x.y</string><key>B</key><string>a&amp;b</string>\
                 <key>C</key><true/></dict>";
    assert_eq!(plist_string(text, "A"), Some("x.y"));
    assert_eq!(plist_string(text, "B"), None);
    assert_eq!(plist_string(text, "C"), None);
    assert_eq!(plist_string(text, "D"), None);
}

#[test]
fn the_job_installs_only_on_the_kexts_staged_report() {
    let job: plist::Value = plist::from_bytes(&job().unwrap()).unwrap();
    let job = job.as_dictionary().unwrap();
    assert_eq!(job["Label"].as_string(), Some(LABEL));
    assert_eq!(job["RunAtLoad"].as_boolean(), Some(true));
    let arguments = job["ProgramArguments"].as_array().unwrap();
    assert_eq!(arguments[0].as_string(), Some("/bin/sh"));
    let script = arguments[2].as_string().unwrap();
    assert_eq!(script, super::script());
    for needed in [
        "archive=/private/var/db/org.stela.Stela.zip\n",
        "app=/Applications/Stela.app\n",
        "\"StelaApp\" = ",
        "if [ \"$report\" = staged ]; then",
        "/usr/bin/codesign --verify --strict \"$new/Stela.app\"",
        "/bin/rm -f \"$archive\" /Library/LaunchDaemons/org.stela.Stela.install.plist\n",
    ] {
        assert!(script.contains(needed), "{needed}");
    }
    // The kext and the script name the property and the report alike.
    let policy = include_str!("../../../../guest/stela-gpu/kext/app_policy.h");
    assert!(policy.contains(&format!("#define STELA_APP_PROPERTY \"{PROPERTY}\"\n")));
    assert!(policy.contains(&format!("#define STELA_APP_STAGED \"{STAGED}\"\n")));
    let status = Command::new("sh")
        .args(["-n", "-c", script])
        .status()
        .unwrap();
    assert!(status.success(), "the script is not POSIX shell");
}

/// Builds `guest/stela-gpu/kext/tests/<name>.c` with the `clang` on PATH, a
/// hosted program that needs none of the build's other LLVM tools.
fn kext_test(name: &str, built: &Path) -> PathBuf {
    let clang = crate::tools::which("clang").expect("a clang on PATH for the kext's host tests");
    let source = crate::tools::root().join(format!("guest/stela-gpu/kext/tests/{name}.c"));
    let program = built.join(name);
    crate::tools::exec(
        Command::new(clang)
            .args(["-std=c17", "-Wall", "-Wextra", "-Werror", "-o"])
            .arg(&program)
            .arg(source),
    )
    .unwrap();
    program
}

#[test]
fn the_kext_c_code_passes_its_host_tests() {
    let built = tempfile::tempdir().unwrap();
    for name in ["app_policy", "host_record", "plugin_report"] {
        let output = Command::new(kext_test(name, built.path()))
            .output()
            .unwrap();
        let printed = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && printed == "ok\n",
            "{name}: {printed}"
        );
    }
}

#[test]
fn the_kext_reads_the_records_stela_efi_writes() {
    use stela_loader::stela_gpu::{HostValue, encode_host};
    let built = tempfile::tempdir().unwrap();
    let program = kext_test("host_record", built.path());
    let record = encode_host(&[
        (
            "CPUBrand".into(),
            HostValue::Text("AMD Ryzen 9 9950X 16-Core Processor".into()),
        ),
        ("HostThreads".into(), HostValue::Number(32)),
        ("HostMemoryBytes".into(), HostValue::Number(u64::MAX)),
        ("SystemModel".into(), HostValue::Text("x".repeat(400))),
    ])
    .unwrap();
    let file = built.path().join("record");
    fs::write(&file, record).unwrap();
    let output = Command::new(program).arg(&file).output().unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!(
            "CPUBrand|s|AMD Ryzen 9 9950X 16-Core Processor\nHostThreads|n|32\n\
             HostMemoryBytes|n|18446744073709551615\nSystemModel|s|{}\n",
            "x".repeat(stela_loader::stela_gpu::HOST_TEXT_BYTES)
        )
    );
}

#[test]
fn the_newest_package_is_found_unless_one_is_named() {
    let root = tempfile::tempdir().unwrap();
    assert!(locate_in(root.path(), None).unwrap().is_none());
    let packages = root.path().join("target/stela-app");
    let mut found = Vec::new();
    for (name, age) in [("package.old", 60), ("package.new", 0), ("other", 0)] {
        let directory = packages.join(name);
        fs::create_dir_all(directory.join("Stela.app/Contents")).unwrap();
        fs::write(directory.join("Stela.app/Contents/Info.plist"), b"").unwrap();
        fs::File::open(&directory)
            .unwrap()
            .set_modified(SystemTime::now() - Duration::from_secs(age + 1))
            .unwrap();
        found.push(directory.join("Stela.app"));
    }
    assert_eq!(
        locate_in(root.path(), None).unwrap(),
        Some(found[1].clone())
    );
    let named = Some(found[0].clone().into_os_string());
    assert_eq!(
        locate_in(root.path(), named).unwrap(),
        Some(found[0].clone())
    );
    let missing = Some(root.path().join("none").into_os_string());
    assert!(locate_in(root.path(), missing).is_err());
    assert_eq!(
        locate_in(root.path(), Some(OsString::new())).unwrap(),
        Some(found[1].clone())
    );
}
