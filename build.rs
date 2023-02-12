fn main() -> std::io::Result<()> {
    prost_build::compile_protos(&["proto/crx3.proto"], &["proto/"])
}
