use frostgate_circuits::sp1::Sp1Backend;
use frostgate_lib::zkplug::ZkBackend;

fn main() {
    // Create test input data
    let test_message = b"Hello, Frostgate!";
    
    // Initialize the SP1 backend
    let backend = Sp1Backend::new();
    
    // Get the program bytes (our compiled circuit)
    let program_path = "/home/tnxl/frostgate/target/elf-compilation/riscv32im-succinct-zkvm-elf/release/frostgate-circuits";
    let program = std::fs::read(program_path)
        .expect("Failed to read program");
    
    println!("Generating proof for message: {:?}", String::from_utf8_lossy(test_message));
    
    // Generate proof
    let proof = backend.prove(&program, test_message)
        .expect("Failed to generate proof");
    
    println!("Proof generated! Size: {} bytes", proof.len());
    
    // Verify the proof
    let is_valid = backend.verify(&program, &proof)
        .expect("Failed to verify proof");
    
    println!("Proof verification result: {}", is_valid);
} 