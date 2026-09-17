fn main() {
    #[cfg(windows)]
    {
        // gpui's default `windows-manifest` already embeds RT_MANIFEST. rustc
        // would add a second copy and winres `set_manifest` a third — MSVC
        // cvtres then dies with CVT1100 / LNK1123. Drop rustc's; keep gpui's;
        // only compile the app icon here.
        println!("cargo:rustc-link-arg=/MANIFEST:NO");
        println!("cargo:rerun-if-changed=../../res/icon/icon.ico");
        let mut res = winres::WindowsResource::new();
        res.set_icon("../../res/icon/icon.ico");
        if let Err(e) = res.compile() {
            println!("cargo:warning=winres: {e}");
        }
    }
}
