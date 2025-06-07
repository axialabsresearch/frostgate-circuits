pub mod sp1;

pub use sp1::Sp1Backend;

#[cfg(test)]
mod tests {
    use super::*;
    use frostgate_lib::zkplug::*;
    
    #[test]
    fn test_sp1_circuit() {
        let backend = Sp1Backend::new();
        // Add tests here
    }
} 